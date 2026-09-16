rule Virus_Hijack_Trojan_GenericKDZ_103545_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3a1e7617561734eea82c71446278e8ac3422a04b421be6775fd672e8c4b0bef"

  strings:
    $s1 = "software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}