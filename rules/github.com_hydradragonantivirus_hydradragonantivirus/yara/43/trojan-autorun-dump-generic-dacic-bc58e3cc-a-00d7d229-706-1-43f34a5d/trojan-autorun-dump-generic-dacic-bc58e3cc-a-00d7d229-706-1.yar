rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_706_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_706_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e605e64e9bc04f9e0e695ec14f266938adb067e5e37debeee8b87c1a862238a"

  strings:
    $s1 = "4eProfessional User " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}