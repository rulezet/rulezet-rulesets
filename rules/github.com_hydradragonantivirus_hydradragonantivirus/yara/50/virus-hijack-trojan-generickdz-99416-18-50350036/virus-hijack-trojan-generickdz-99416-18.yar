rule Virus_Hijack_Trojan_GenericKDZ_99416_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d82c2a455bdeae837077416f44e0ba9699e93716e9b69c97aaeed75a465e8c4"

  strings:
    $s1 = "-'User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}