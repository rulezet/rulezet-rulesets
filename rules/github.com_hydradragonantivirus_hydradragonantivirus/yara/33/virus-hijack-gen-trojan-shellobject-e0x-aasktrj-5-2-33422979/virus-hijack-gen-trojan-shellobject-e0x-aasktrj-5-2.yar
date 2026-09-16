rule Virus_Hijack_Gen_Trojan_ShellObject_e0X_aaSKtRj_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e0X@aaSKtRj_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba4d03c54482ef46d22e2438e4ae9ba263373e031a99cf20909c3effca01d0b5"

  strings:
    $s1 = "*Niter" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}