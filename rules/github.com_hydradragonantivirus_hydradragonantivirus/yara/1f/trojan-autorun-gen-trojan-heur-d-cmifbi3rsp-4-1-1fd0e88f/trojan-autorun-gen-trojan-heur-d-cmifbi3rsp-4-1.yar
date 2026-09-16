rule Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb71c09f3f844789db1418004c37b177959a4f030b05434d24d3ea6dcac7f8df"

  strings:
    $s1 = "@4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}