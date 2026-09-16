rule Virus_Hijack_Trojan_GenericKDZ_79663_60_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46bfbd996886d6b78abcb7b72c08f6d88572e0048883e06d0120f22731111d33"

  strings:
    $s1 = "(*gleN" fullword ascii
    $s2 = "tEaD)c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}