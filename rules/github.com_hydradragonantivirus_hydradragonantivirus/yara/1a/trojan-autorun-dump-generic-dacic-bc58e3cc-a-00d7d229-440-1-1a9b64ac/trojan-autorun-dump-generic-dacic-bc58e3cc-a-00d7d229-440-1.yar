rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_440_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_440_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b079c6ba2927773322439fde551a51ebda6cf54368f3241684d94cc3d705a5"

  strings:
    $s1 = "0If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}