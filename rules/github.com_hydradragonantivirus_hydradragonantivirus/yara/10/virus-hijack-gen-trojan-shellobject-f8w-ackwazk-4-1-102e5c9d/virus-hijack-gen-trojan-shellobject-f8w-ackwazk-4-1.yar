rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e95bada559d67e6a4757b16b7e2d79c90a6a3b50e6b85e5f2ed7e0c6d27b42"

  strings:
    $s1 = "Python 3.7." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}