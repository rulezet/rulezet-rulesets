rule Virus_Hijack_Trojan_GenericKDZ_105924_493_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_493_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8d6e969d2800ebd3c5cf2ff4f0286c3fec8c9fb6e4d7e6377e06e2b9fa45e1c"

  strings:
    $s1 = "E@kItAR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}