rule Virus_Hijack_Trojan_GenericKDZ_74550_52_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_52_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a57496833ab26f7941a187aa0a40a9f28edd5168e04abdedb27674a26294524d"

  strings:
    $s1 = "bait>T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}