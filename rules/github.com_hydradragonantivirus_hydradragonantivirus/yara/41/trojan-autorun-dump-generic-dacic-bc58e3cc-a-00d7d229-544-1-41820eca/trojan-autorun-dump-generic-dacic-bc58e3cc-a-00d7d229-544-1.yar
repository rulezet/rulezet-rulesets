rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_544_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_544_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e710a42cc9a1b17801df0fe5b412c1fab948a2d62cb086879aad9a8ada9ef18"

  strings:
    $s1 = "5Ycreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}