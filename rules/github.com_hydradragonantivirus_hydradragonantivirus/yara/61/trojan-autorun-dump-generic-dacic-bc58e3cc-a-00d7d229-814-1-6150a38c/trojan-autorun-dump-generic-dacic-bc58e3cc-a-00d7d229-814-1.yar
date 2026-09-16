rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_814_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_814_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a76de2c8257d5bff362374c3dae18f0a7ee72605eb752d52bac3f44fc0eba5"

  strings:
    $s1 = "Eof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}