rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_351_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_351_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f83e6e058a341fb2e13be76719297feb32d9fc4c9f196ec5f31c7532caf92b47"

  strings:
    $s1 = "Current@CK" fullword ascii
    $s2 = "Current %J" fullword ascii
    $s3 = "Count$SI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}