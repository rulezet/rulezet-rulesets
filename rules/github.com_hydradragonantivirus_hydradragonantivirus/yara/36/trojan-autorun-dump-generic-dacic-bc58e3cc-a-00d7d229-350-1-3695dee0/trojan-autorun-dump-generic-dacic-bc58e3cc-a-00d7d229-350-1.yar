rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_350_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_350_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f93d36e894a34aae5c19ed76f7de064a58cc30230ccbce34d56a429bb261cfb0"

  strings:
    $s1 = "6iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}