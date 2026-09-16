rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_55_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9cb61530b137fc164d2b7cc89a8b530202634db1828ea8fe0918edeedc3db43"

  strings:
    $s1 = "Uzcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}