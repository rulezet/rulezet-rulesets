rule Virus_Hijack_Trojan_GenericKDZ_98113_278_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_278_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d54815a285e403c8918d2d0c486824fb38e205e2b1a99b443b3603a90af8b165"

  strings:
    $s1 = "g#$aBIr" fullword ascii
    $s2 = "PLEB]9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}