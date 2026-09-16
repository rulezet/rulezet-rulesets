rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_27_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_27_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20e49019222a2e4495de30b57dbfa03d803af903584b1e1fdc612c79acd0f0bc"

  strings:
    $s1 = "c;<PRof}w" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}