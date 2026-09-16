rule Virus_Hijack_Trojan_Peed_Gen_64_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b965cbeda8ae7d832802369d2bd6918f3846334f1df09457ddb502dc1a3bf87c"

  strings:
    $s1 = "liKe,]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}