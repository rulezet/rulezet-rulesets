rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "374850bf37dea7069c63d4bd65bb5150edd81793ebf0355040ea875389527f4b"

  strings:
    $s1 = "x)SEgO" fullword ascii
    $s2 = "DW>yaff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}