rule Virus_Hijack_Trojan_GenericKDZ_99416_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867083b7f1e47315ee5099e87a2565589633b9089ddf787e51a6945bca227b94"

  strings:
    $s1 = "bHUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}