rule Virus_Hijack_Gen_Trojan_ShellObject_cuW_ai99xDb_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.cuW@ai99xDb_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d96d28b19928ffa81c9e466b70b732d163d1321bced0ef2907ff3acba5d43cd7"

  strings:
    $s1 = "5(@yaRB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}