rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_194_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5d382b42fd830432c8877a01910d4ee17dd6f255bd2760c75ea4e20cb22a787"

  strings:
    $s1 = "^iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}