rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_211_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_211_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdac090e57a93946a86723a2ce13e25dd3adba68461bee5cc7b9c2c23ef3c63a"

  strings:
    $s1 = "NviLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}