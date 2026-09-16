rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_32_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_32_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "303096dd8039f6afd090f03d562de6532aea79f73d4dd2fbd9e5686cdbfd45c7"

  strings:
    $s1 = "rEcCy?_" fullword ascii
    $s2 = "b*%roam" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}