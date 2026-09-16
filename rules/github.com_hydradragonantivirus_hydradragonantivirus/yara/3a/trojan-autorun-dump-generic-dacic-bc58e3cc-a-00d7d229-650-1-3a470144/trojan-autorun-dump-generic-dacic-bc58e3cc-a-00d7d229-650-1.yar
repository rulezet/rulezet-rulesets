rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_650_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_650_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c7c8600196a33730c60d58c623cb4490009fe72c18281c44f0f1665bc66055"

  strings:
    $s1 = "W-create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}