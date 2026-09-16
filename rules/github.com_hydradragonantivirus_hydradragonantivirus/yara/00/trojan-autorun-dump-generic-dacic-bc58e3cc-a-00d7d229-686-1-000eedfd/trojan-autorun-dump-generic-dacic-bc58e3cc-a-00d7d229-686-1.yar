rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_686_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_686_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fb9846ac72d1431b7431acb8c2516e56b4ab4a9024db66145a37d9c30c08128"

  strings:
    $s1 = "5Qcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}