rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_301_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_301_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64610edbaa29878693eb0513d42c39e34e17f91053b9e952a0e8fda3c543bd9c"

  strings:
    $s1 = ")hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}