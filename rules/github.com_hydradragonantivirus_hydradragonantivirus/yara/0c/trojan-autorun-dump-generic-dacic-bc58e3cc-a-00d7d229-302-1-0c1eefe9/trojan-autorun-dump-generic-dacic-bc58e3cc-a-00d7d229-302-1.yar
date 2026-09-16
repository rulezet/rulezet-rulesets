rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_302_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_302_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dee383e4b246c2d6a232c9d411a75ede1de8965c2221856fb64cc129cbf5647d"

  strings:
    $s1 = "8iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}