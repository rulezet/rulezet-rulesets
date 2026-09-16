rule Virus_Hijack_Trojan_GenericKDZ_99416_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df6c8c2bea703012eeb13d33421354afeec5c1a5db0c4efefce175fe261914ef"

  strings:
    $s1 = "2NUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}