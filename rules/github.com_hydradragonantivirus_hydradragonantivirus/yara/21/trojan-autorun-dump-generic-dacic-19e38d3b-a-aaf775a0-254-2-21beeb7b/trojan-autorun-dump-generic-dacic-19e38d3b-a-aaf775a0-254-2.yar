rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_254_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_254_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "225febddb27d1a197367d4773aec9f21ac99b2a66c422dd0244aaab30db08ec0"

  strings:
    $s1 = ">H/}AEoN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}