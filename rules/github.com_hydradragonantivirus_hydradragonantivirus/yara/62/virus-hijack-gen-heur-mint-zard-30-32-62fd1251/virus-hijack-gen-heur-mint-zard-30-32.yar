rule Virus_Hijack_Gen_Heur_Mint_Zard_30_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5243a9a4d0929fb720b44c5c994d95d2cec234675ca7d43d5cbb3e0b503d21f9"

  strings:
    $s1 = "Bonelessness" fullword wide
    $s2 = "Rascally" fullword wide
    $s3 = "p[(AXES" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}