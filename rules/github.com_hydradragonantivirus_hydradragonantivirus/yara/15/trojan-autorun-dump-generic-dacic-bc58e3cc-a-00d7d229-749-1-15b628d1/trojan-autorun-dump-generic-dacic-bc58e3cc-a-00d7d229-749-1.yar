rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_749_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_749_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4967ed82c5e7f511b9438e31c428005da895771e349c5fcfbe5485d19f44e11"

  strings:
    $s1 = "YEof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}