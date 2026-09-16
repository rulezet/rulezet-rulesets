rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_272_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_272_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2cd46eed8c838d8e7c9393e9716e198c462258074de8c6e782e504e9aa15b6f"

  strings:
    $s1 = "Y:hatH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}