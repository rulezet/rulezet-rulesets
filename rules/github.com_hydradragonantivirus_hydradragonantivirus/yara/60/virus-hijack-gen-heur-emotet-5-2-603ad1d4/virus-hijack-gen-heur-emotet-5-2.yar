rule Virus_Hijack_Gen_Heur_Emotet_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Emotet.5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1244ae1ec20dc3f2d69fd3652f38c035b57374786100c5f11cf3b824543148"

  strings:
    $s1 = "dropflower" fullword wide
    $s2 = "textilist" fullword wide
    $s3 = "Unbasedness" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}