rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_253_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_253_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e483f9d830ecaf496a7af3d91690de7045b22a03df8da9690a51b0598fa023a8"

  strings:
    $s1 = "LOuP]SuP]Iq" fullword ascii
    $s2 = "Z^<PLUd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}