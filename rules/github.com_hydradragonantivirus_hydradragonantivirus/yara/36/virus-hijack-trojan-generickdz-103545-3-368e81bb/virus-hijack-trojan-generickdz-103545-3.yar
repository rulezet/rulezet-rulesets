rule Virus_Hijack_Trojan_GenericKDZ_103545_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb633eb032e950630ffdc32bb975e842c28e7a3c11b19287f52ca3c508d6f657"

  strings:
    $s1 = "^@software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}