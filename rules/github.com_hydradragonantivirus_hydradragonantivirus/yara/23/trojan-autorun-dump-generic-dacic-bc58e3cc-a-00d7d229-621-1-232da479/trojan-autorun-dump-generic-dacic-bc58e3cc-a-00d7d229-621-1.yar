rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_621_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_621_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc9711960262b42fd03c15c10409ce9a798a8f9f1aded647140be0c1f8f8a4f"

  strings:
    $s1 = "create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}