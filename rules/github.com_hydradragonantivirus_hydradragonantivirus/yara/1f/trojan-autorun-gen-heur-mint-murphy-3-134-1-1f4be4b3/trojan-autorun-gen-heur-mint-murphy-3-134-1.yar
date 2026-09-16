rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_134_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7df5223be94f008dd30a074ae6f158fb999ec4b4651392390dfcebe3b9185b1"

  strings:
    $s1 = "LOuP]SuP]Iq" fullword ascii
    $s2 = "Z^<PLUd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}