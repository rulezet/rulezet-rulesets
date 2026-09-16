rule Virus_Hijack_Trojan_GenericKDZ_74550_276_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_276_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e86f0fd7b8dfdb2811645b3039b8c3099e881a7e466dab3586ac6ba5fe30b234"

  strings:
    $s1 = "bRag:P6" fullword ascii
    $s2 = "\",pOhA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}