rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_136_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "888f59ff63ee94a2c2cc9a875988903b2bfac0a93928f5846b7905dfb77b89ec"

  strings:
    $s1 = "{KiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}