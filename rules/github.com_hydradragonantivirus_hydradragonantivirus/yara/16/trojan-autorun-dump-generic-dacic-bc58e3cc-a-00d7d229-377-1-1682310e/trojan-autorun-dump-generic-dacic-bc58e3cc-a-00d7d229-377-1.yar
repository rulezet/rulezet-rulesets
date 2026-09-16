rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_377_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_377_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af709a70f9f3ad9621c5be5b5d41dd2abf8ec6a9fa99bc82154fc478ad15ee77"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}