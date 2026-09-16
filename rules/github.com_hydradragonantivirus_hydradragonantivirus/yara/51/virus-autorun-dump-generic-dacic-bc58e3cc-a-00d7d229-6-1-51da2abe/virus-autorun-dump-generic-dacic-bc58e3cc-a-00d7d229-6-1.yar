rule Virus_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9033dd93598542aad40f1d90674f8b4965cd8abcd500b4c7561f40054b1bf82f"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}