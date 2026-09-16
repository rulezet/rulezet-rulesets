rule Virus_Hijack_Trojan_GenericKDZ_103545_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "779afac6040dde0b6cdd096f679393871264ff29d6bc0e4e3fe8f09fc8c827a4"

  strings:
    $s1 = "bsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii
    $s2 = "gAnE}@$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}