rule Virus_Hijack_Trojan_GenericKDZ_105924_407_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_407_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a7231f0abda77403e84cd8aea54f3b168d2eeb9300754c44665b75ccf2e5d59"

  strings:
    $s1 = "*,TOPH" fullword ascii
    $s2 = "}FRanC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}