rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "450a36d41287a726777f70c027b82140fd92512e29f3b4edc4ff173a6907652f"

  strings:
    $s1 = "Microsoft Ireland Operations Limited makes the limited warranty. To make a claim unde" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}