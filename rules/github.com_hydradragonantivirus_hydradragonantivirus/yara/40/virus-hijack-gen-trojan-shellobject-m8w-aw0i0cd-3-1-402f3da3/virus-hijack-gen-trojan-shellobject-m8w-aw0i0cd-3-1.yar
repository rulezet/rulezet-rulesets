rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4151858e6714f1a5d82ff801be2e7cc5bab9ac13f5c83acc1b37cbf3743887bb"

  strings:
    $s1 = "TERp!A" fullword ascii
    $s2 = "}`gOwN" fullword ascii
    $s3 = "V=r:STEY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}