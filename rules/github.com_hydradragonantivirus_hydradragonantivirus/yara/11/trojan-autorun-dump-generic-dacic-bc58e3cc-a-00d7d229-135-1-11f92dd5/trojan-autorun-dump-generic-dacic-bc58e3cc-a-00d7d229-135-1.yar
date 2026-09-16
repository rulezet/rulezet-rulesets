rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_135_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_135_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56dc1c5bc49b3e97d6c556f9653c5166b866a0592fe59c7f75a00ad84d941262"

  strings:
    $s1 = "9iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}