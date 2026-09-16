rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_303_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_303_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ece3cefafc1c49e1f81c5e2c5cbb15639c3aab955d3270b2730478648499408"

  strings:
    $s1 = "sWay`n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}