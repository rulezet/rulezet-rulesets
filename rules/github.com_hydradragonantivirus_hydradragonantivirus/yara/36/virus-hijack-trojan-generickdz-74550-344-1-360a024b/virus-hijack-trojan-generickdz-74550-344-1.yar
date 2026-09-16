rule Virus_Hijack_Trojan_GenericKDZ_74550_344_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_344_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2faf304c34ab63703db26098722f91e63da4312312818e9bf2167bbf559773d0"

  strings:
    $s1 = "5[gOUP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}