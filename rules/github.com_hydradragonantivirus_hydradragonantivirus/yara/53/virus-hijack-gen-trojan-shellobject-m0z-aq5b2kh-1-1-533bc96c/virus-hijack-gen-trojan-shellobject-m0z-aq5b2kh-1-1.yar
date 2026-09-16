rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aq5b2kh_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aq5b2kh_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb8cdce02656ec748ac116be07440a09bb38d6b864c1c9c21ff37566ac268f6a"

  strings:
    $s1 = "lIke]." fullword ascii
    $s2 = "'S]PUli" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}