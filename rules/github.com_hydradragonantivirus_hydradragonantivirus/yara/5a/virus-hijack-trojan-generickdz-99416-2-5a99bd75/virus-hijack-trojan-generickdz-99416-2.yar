rule Virus_Hijack_Trojan_GenericKDZ_99416_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e63d5aedb5a70c2329eaa0e7463481e07b254342222728ee570b3e9292c7fcd0"

  strings:
    $s1 = "QUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}