rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_574_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_574_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f56febd7e49e54ec238e14cfc0d5df5389412b1eebc9af8b32f77d55a7f0dac"

  strings:
    $s1 = "X3of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}