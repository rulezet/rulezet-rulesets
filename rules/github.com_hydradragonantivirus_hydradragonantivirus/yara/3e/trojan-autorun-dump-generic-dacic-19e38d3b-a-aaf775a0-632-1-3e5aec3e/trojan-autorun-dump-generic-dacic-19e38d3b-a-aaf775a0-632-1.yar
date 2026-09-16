rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_632_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_632_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd4fd505bd1860db2fe4dca4697e8829501d8b5a409c2060df1a8bd735084a9c"

  strings:
    $s1 = "Yare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}