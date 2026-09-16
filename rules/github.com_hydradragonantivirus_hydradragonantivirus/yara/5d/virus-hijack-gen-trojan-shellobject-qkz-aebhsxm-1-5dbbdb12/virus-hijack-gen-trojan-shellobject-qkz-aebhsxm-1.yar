rule Virus_Hijack_Gen_Trojan_ShellObject_qKZ_aeBHSxm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.qKZ@aeBHSxm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83c39b8610ce5ade7ea77423ae2743e62c0cd6a21839122026bc08bb7859008a"

  strings:
    $s1 = "r=%moLY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}