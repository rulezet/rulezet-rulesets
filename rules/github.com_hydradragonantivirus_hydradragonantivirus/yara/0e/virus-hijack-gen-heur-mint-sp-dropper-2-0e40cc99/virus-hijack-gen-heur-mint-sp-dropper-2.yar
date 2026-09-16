rule Virus_Hijack_Gen_Heur_Mint_SP_Dropper_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Heur.Mint.SP.Dropper.2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dca213618c46479f580970629e47c65d7ca0b2fb10b407df2f9ea9dc81e530de"

  strings:
    $s1 = "AutoIt v3 Script : 3, 2, 4, 9" fullword wide
    $s2 = "GYPS?;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}