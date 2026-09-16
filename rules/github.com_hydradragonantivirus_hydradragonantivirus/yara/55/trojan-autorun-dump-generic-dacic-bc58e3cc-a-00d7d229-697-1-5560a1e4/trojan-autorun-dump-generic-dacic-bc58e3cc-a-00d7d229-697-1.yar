rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_697_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_697_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f60fbf1ae640e6f3b017a96a7fc768f775794c217582fb5d0078b4b1c381c49"

  strings:
    $s1 = "}4create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}