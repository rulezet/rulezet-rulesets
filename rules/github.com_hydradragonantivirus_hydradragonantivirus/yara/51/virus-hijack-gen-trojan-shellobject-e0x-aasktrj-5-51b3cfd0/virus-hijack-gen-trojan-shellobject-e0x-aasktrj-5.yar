rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a35c8695e8192d054b457855a52bcdc960b92fae2c9e30dcd2e3cf817832191"

  strings:
    $s1 = "functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}