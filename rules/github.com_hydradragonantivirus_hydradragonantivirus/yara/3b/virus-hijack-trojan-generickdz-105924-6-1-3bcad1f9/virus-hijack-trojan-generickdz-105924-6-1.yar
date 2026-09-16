rule Virus_Hijack_Trojan_GenericKDZ_105924_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6e8233a02082ad1956e7e2d1ecc13703cdb6fc4fc7b3e58b148da6d32b90b9c"

  strings:
    $s1 = "<NEck`@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}