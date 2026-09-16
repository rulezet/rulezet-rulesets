rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_409_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_409_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecea7a12a9ec89492dcea0c9ad6cc022f3ec1de0fe8fa94e9ddbe187482a6f1c"

  strings:
    $s1 = ";posted a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}