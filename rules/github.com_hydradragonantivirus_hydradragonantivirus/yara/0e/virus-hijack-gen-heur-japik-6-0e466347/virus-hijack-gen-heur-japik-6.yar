rule Virus_Hijack_Gen_Heur_Japik_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Japik.6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8cb8dad3f198c0710209d1df6f375076fe267d7ec53f30ed9325a9f48a63004"

  strings:
    $s1 = "orvietan" fullword wide
    $s2 = "Stibiconite" fullword wide
    $s3 = "Sacking" fullword wide
    $s4 = "?Cell%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}