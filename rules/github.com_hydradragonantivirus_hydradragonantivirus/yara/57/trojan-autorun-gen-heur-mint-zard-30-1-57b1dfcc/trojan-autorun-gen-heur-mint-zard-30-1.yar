rule Trojan_Autorun_Gen_Heur_Mint_Zard_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Zard.30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0ad9c6b2000de1844c9e26e8559dba88fa9b05c456dff3402ff45c87efcd79d"

  strings:
    $s1 = "Portions Copyright (c) 198" fullword ascii
    $s2 = "Sync!_iz3" fullword ascii
    $s3 = "L FROM:<" fullword ascii
    $s4 = "k/)From" fullword ascii
    $s5 = ">!Aqua" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}