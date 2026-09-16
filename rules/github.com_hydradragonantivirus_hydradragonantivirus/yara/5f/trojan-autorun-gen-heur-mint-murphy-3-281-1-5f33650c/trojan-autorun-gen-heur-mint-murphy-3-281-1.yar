rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_281_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_281_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8340e5d6aaee82569387cd640168a7d335f7fdda14f61e9f6c85acca94bd1134"

  strings:
    $s1 = "W}hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}