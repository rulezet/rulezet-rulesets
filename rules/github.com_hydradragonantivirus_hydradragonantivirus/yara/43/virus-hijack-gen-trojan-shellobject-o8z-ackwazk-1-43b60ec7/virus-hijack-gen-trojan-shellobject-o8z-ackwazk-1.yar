rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aCkwazk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aCkwazk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8a64f8809d37f49d400571a6a9032b981ca89b5995241cc43bc9746372e8bb5"

  strings:
    $s1 = "uNby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}