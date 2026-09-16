rule Virus_Sysbot_Gen_Heur_ManBat_1_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20c34d6f90cab4e4401e6e6bcb0a58d9d09572eea9073e981eaca1c6d2237bc4"

  strings:
    $s1 = "YaJe'%" fullword ascii
    $s2 = "*%TArO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}