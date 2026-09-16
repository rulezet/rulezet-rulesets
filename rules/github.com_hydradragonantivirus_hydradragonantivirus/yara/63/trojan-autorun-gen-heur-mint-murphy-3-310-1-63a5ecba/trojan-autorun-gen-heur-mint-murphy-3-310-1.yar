rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_310_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_310_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d7c633cc9b8359624451ce8421d994ee80ae2680b01ba2a590bd9510879db7d"

  strings:
    $s1 = "@Q4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}