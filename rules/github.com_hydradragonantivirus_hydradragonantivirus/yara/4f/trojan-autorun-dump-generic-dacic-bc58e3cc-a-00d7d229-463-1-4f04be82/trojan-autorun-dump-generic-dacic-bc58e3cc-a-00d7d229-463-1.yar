rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_463_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_463_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "703194e0b108d3425b69bc3389025cb9b1eb1e410a3c1b5b5e12e7d8f629f083"

  strings:
    $s1 = "+iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}