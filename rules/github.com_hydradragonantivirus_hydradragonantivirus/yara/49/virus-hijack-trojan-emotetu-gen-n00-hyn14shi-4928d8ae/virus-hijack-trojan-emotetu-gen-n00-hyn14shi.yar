rule Virus_Hijack_Trojan_EmotetU_Gen_n00_hyn14Shi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.EmotetU.Gen.n00@hyn14Shi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0099257b9cffeaab5209a096c1e89628137b5aac13a0f11194766356e0752909"

  strings:
    $s1 = "underfeeling" fullword wide
    $s2 = "Morrowmass" fullword wide
    $s3 = "Abstractiveness" fullword wide
    $s4 = "HALA@ED" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}