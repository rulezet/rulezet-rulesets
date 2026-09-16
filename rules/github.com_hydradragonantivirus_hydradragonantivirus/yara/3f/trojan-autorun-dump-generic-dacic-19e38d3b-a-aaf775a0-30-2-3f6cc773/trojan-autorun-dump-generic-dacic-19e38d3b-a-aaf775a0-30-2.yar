rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_30_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_30_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45519b6a30d0e4de52aebda09b742eebf673213d479e2997ceb17ad960dd0c65"

  strings:
    $s1 = "mAnD`]n" fullword ascii
    $s2 = "*PF{fLeD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}