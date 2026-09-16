rule Trojan_Autorun_Generic_Dacic_06B5CF0E_A_DD3400CB_11 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.06B5CF0E.A.DD3400CB_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c19389c3e3cc5ff3929859b31c7d52fb06cd7c140ccf6b70793f09265d20f5a6"

  strings:
    $s1 = "Ufunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}