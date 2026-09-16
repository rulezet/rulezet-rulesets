rule Virus_Hijack_Trojan_GenericKDZ_105924_474_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_474_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b6e70339335a6a8eff30d7d9081e69021b9e7d90445a0c3eac144f843f0657d"

  strings:
    $s1 = "aUBE!!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}