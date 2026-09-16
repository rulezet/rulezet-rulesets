rule Trojan_Autorun_Gen_Trojan_Heur_D_cmHfbGeK0bf_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmHfbGeK0bf_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e1dabbcb5d5d55a585efb1d01b461a0fed851c5d803694e819e10ab61de211d"

  strings:
    $s1 = "ihundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}