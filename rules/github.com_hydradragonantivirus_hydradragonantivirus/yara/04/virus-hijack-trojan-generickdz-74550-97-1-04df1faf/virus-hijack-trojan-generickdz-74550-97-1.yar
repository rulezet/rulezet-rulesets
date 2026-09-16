rule Virus_Hijack_Trojan_GenericKDZ_74550_97_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_97_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d486550107560d21ce31d0ae1bcd6b80a2203f43e41d597759e496011b6fed"

  strings:
    $s1 = "a{P[DEPA]%" fullword ascii
    $s2 = "I[lOss" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}