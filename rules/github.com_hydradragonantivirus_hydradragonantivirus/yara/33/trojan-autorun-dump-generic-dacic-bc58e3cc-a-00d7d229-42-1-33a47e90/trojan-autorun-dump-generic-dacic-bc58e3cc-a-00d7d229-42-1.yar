rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_42_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8281456c89b38e46debedf78a3b4fac08a9a07e67a415252ca1ab8f1a18d510"

  strings:
    $s1 = "BVare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}