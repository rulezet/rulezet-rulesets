rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_221_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_221_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9131359268037156f0febffe05210583e1c04612dd49d860084aa8b04c67dcba"

  strings:
    $s1 = "Current(GK" fullword ascii
    $s2 = "Count,~I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}