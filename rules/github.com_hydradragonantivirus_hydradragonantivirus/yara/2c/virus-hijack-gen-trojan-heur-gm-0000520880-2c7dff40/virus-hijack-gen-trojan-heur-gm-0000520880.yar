rule Virus_Hijack_Gen_Trojan_Heur_GM_0000520880 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.Heur.GM.0000520880.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76d98957bcdc15457684303a809b3fccdf3100361db750a901ac7649159e4f6b"

  strings:
    $s1 = "swow:]5" fullword ascii
    $s2 = "RAsp)I<" fullword ascii
    $s3 = ",*VlEi" fullword ascii
    $s4 = "F:feAL" fullword ascii
    $s5 = "Qn%vaiR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}