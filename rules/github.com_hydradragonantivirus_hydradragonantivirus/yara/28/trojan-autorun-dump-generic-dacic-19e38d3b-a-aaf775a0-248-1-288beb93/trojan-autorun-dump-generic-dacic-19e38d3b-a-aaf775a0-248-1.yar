rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_248_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_248_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8caafa8e6b02d3724331866ad942b6ed34c3acdbcd777297fa4b8dc5477fc9d0"

  strings:
    $s1 = "sAgE}S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}