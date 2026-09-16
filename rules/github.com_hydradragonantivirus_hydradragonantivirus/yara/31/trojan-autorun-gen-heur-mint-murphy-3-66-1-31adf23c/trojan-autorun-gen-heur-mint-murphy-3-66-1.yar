rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_66_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b09582ad634ae3254967033a00106ddff2d3452625b20ef6b0a18dbcd9f5433d"

  strings:
    $s1 = "microsoft.com/office/backup. You may not distribute the backup co" fullword ascii
    $s2 = "e option to convert your trial rights to subscription or" fullword ascii
    $s3 = "a third party without restriction on the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}