rule Virus_Hijack_Gen_Heur_Mint_SP_Urelas_1_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.SP.Urelas.1_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcd7e126fa7025672c962f9fb8cf1849ff8f79a15e96450da5e9abf178dc70b8"

  strings:
    $s1 = "Xiphias" fullword wide
    $s2 = "Unwifely" fullword wide
    $s3 = "Reoccurrence" fullword wide
    $s4 = ")>0-$)7&'$8:1@$$Dite" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}