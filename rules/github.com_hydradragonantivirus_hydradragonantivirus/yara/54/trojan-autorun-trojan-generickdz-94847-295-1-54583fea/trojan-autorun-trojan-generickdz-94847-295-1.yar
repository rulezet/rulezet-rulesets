rule Trojan_Autorun_Trojan_GenericKDZ_94847_295_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_295_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7712ee933a507cfd32852825237bb82876072c5dac4d97583be74fb48eaf03ad"

  strings:
    $s1 = "31=%taUt" fullword ascii
    $s2 = "C1=%taUt" fullword ascii
    $s3 = "561=%taUN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}