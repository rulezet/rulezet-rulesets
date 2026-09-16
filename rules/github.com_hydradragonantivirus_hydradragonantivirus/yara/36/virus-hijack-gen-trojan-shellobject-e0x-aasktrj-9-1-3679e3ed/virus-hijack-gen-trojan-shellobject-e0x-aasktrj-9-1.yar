rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dbdda0cc2e202d90dfb68be3be1beea4d6bb16f67bd6e5878849ecf88ab2024"

  strings:
    $s1 = "!This program cannot be run in MZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}