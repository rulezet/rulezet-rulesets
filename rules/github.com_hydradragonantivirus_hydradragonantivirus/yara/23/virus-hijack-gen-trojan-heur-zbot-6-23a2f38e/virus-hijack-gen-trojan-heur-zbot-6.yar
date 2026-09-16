rule Virus_Hijack_Gen_Trojan_Heur_Zbot_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.Heur.Zbot.6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7964ad668e3af7e0ae1be2ea2b83428e918cc3be6761abd3fa78a11fdfbb6801"

  strings:
    $s1 = "Ely Bumps Breed" fullword wide
    $s2 = "Fort Moles Mcgee" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}