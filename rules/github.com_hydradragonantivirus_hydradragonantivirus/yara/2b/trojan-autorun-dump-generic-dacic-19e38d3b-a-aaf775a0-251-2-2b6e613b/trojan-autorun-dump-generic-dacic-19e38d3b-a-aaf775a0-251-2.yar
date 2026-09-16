rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_251_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_251_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a922f564a727fd6988eeee703a3b0d17bc900ccbdb9547dafde84221be6422d7"

  strings:
    $s1 = "dE[SAlT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}