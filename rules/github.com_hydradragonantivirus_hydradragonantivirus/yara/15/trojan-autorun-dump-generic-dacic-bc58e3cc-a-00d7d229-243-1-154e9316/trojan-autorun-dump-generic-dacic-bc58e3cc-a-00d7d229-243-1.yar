rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_243_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ca13b68514247fed4a5143dda6d25b6a47061932f5a75599497662f4880ef9f"

  strings:
    $s1 = "hiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}