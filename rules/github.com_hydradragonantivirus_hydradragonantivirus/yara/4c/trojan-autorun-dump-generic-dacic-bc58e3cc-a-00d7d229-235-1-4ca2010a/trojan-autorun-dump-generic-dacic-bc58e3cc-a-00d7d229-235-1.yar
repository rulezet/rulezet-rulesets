rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_235_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_235_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3011dd914b2b6ea762b11309aa71aac17223b85579fe6a6f2c7b44216eead1d5"

  strings:
    $s1 = "%?Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}