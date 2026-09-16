rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_595_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_595_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab3c0ddee26856e663384d97109c0b2b5c835204faf965ad2666b03c0a4d3b1"

  strings:
    $s1 = "Cyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}