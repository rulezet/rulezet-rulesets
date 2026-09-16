rule Virus_Hijack_Trojan_GenericKDZ_99416_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b2848ce78693de177d9e98564d559e51f68986e77adb7bf2400b8d5917b7778"

  strings:
    $s1 = "AiUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}