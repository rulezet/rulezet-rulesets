rule Virus_Hijack_Trojan_GenericKDZ_74550_181_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_181_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "123fed2b64dc4ac7c0fee935d057d881e6cb7ee821d7f53f0ec5385b10a2368f"

  strings:
    $s1 = "proG}S&" fullword ascii
    $s2 = "N<bOnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}