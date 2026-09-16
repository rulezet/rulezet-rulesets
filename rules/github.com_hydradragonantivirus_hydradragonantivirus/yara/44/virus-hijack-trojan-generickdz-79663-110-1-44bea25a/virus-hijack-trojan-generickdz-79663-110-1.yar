rule Virus_Hijack_Trojan_GenericKDZ_79663_110_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_110_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b688a2f3714e0c2f761add8b5fba351476160e157c1605784ad77ff2a2c49ea1"

  strings:
    $s1 = "TOUP<M" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}