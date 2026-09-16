rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOIIYRj_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOIIYRj_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1d3cf03691648b7d5092312e64f2bd2d6801399f6362a7a4c827e1476940668"

  strings:
    $s1 = "Server," fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}