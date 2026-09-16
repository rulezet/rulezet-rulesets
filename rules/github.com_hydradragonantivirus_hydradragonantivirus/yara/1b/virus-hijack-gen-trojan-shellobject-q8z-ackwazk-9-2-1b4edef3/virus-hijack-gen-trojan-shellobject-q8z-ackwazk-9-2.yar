rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c01b5947ce0a224ece026d744eec8f93d3a7f0231a59e725ed62497fb0d759c"

  strings:
    $s1 = "]sOle:^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}