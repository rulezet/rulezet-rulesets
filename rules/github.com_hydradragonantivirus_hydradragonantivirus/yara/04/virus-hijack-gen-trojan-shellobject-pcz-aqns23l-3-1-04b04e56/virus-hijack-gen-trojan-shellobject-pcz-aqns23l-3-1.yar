rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fdc78e10bc18195b6539b49da2daa5718c6e7847c261cd5f6f488044516414b"

  strings:
    $s1 = "_{STAm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}