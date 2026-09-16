rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_104_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "143d4e7b9c15ae1b7eaadbe7733ba50406dbd8e38f6f0a0e4ea4376526a79624"

  strings:
    $s1 = "SVIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}