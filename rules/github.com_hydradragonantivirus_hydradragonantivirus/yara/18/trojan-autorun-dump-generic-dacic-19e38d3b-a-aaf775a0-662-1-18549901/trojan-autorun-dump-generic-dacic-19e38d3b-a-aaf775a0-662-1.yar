rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_662_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_662_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46a0ef41057300ac803721587ecbd7ceae6023201b407796980ebe97ba88d129"

  strings:
    $s1 = "|Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}