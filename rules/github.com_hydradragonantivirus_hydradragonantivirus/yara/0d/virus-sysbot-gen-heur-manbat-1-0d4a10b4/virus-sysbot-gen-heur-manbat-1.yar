rule Virus_Sysbot_Gen_Heur_ManBat_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Heur.ManBat.1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99e7f9ca6e72c8ca630a21460831d2afce64d22f06595c56520e607c429f891a"

  strings:
    $s1 = "@~~@Java Machine@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}