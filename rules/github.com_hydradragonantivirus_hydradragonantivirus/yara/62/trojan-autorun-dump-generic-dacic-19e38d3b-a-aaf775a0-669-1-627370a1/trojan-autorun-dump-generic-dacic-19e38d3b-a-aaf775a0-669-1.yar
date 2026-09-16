rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_669_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_669_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5cce7c6a118f48ac8a20df293f501053fe8b6203afa8df89108e8f1fc1f7403"

  strings:
    $s1 = "-are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}