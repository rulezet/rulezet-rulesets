rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_732_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_732_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf35c7eb2128d913509fc9ed35a689c93e43a38afc0f528f61ad4edca14d75c"

  strings:
    $s1 = "user minimum tabl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}