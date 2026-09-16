rule Virus_Hijack_Gen_Heur_Mint_Zard_30_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.Zard.30_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b72fbe36a5e14d01e8d65cae974dd12506ee0ef51921c513a422c36db266ed"

  strings:
    $s1 = "t+ IntegratX with SO(" fullword ascii
    $s2 = "Termin*b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}