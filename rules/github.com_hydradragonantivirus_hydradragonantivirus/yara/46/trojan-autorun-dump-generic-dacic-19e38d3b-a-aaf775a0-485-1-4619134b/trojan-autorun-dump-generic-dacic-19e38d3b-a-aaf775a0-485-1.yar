rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_485_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_485_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c61882e933e9bf93dc94fe6c325a0e6232b9f403a21a3f4d35ac90546965c1d7"

  strings:
    $s1 = "w!YElt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}