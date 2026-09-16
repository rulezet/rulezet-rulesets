rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_319_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_319_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "153552b2afa931a82e572cbe8460834c1ea32fe0f6ee1c161ee16e25d2e4cf0b"

  strings:
    $s1 = "KIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}