rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_559_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_559_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d8402f0293be3e38311d4b3529a1b58a4f696cf9290744d899c965f209242eb"

  strings:
    $s1 = "Icounted as \"n\" processors. For the Healthcare Transaction Base program, only the processors on which Internet Application" fullword ascii
    $s2 = "student enrolled in your institution counts as 25% of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}