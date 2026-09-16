rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_187_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e9d6263c46e6b51b041b656a4ecad1131eb8bfc86f7a7519f98ccb977042680"

  strings:
    $s1 = "I]iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}