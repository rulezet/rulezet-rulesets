rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_aCkwazk_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@aCkwazk_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8a6d22a082ae6ac700ebaf28b743399a6967e39e83b6930e655553ef6c0c8db"

  strings:
    $s1 = "qby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}