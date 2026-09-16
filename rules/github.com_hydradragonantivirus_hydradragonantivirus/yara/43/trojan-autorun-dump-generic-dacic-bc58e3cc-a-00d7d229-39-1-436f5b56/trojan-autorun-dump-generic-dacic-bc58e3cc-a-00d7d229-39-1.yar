rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_39_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_39_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81626547210e4ebc70607f9bbc79b2e87e68fe1e187b72f72b703920950930b7"

  strings:
    $s1 = "nare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}