rule Virus_Hijack_Trojan_GenericKDZ_103545_36 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3cd73809efd17b35f5d3cd6c62a1b0852bbb29ec4028af9a9ad8f8862e34e57"

  strings:
    $s1 = "Ssoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}