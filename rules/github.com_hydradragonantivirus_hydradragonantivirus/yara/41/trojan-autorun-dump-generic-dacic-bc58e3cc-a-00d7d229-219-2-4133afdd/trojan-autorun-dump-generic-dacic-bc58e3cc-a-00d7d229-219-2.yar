rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_219_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_219_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3eb89c5fe1e820b0ba694c4aeab1351999630b490d988b4dd698753ab8eb7dc"

  strings:
    $s1 = "B(format != NULL)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}