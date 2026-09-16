rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db23aafe22353ead2447316b0b2cd93ce1781548e667f099f7d17d88f9215025"

  strings:
    $s1 = "THOUGH WE DO NOT, YOU CA NNOT RECOVER MORE THA N YOU PAI`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}