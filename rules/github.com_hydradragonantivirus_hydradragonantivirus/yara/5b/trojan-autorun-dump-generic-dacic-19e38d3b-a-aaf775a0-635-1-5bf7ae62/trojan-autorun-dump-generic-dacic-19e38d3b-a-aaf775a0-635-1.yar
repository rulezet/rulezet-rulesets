rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_635_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_635_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6c5810d1df4b2c1772faa9acf24e288f32b374fdb09903c0b5719cc12af90b1"

  strings:
    $s1 = "8iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}