rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_274_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_274_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98d2a27315b2d6f7549c8075bebd9b3ff970fb013e7e51466962f225846d32a2"

  strings:
    $s1 = "Clue#!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}