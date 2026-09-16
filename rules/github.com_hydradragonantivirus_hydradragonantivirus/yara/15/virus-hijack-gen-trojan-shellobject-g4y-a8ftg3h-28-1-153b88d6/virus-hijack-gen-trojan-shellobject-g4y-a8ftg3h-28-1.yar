rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_a8fTg3h_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@a8fTg3h_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31c3b8b6800a7b56aed10c0007b2441794d365f9ea7d275ef251c31bdacfac8f"

  strings:
    $s1 = "S<FonS" fullword ascii
    $s2 = "RAKI#O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}