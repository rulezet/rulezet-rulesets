rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_66_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fde668541d114816c5904ebc96d90e9eada08a626dd26c629ef0897ca059c87"

  strings:
    $s1 = "conn%f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}