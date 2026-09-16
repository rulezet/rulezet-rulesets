rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_719_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_719_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc0f15702a0555e3f7f98dd30016f07983f36367249dae27ea52c98ae6195879"

  strings:
    $s1 = "mcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}