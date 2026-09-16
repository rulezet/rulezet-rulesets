rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_761_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_761_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d2eb01e61e49c719f5866bd49d43de1b99b3cce0fbdf1a074e1498ff09b6486"

  strings:
    $s1 = "Syour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}