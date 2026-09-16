rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_179_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_179_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba9795f294e572ba6fd6f73a209c27ecab396aef3898955de7db0aa0ec3ed001"

  strings:
    $s1 = "You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}