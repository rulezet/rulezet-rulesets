rule Virus_Hijack_Trojan_GenericKDZ_103545_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "188c6b474f73ebca951b9722003ffe63bcaf97934609353e0628a3c9761cc090"

  strings:
    $s1 = "msoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}