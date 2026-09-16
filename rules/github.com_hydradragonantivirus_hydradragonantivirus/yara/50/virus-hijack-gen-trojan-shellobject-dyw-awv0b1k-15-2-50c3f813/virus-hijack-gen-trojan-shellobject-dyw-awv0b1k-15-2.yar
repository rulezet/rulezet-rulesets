rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aWV0B1k_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aWV0B1k_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c51fd23a5524f2ae9dab13780e4ccb9efea41f21575e68d16fd8fb0c287b115"

  strings:
    $s1 = "U:shOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}