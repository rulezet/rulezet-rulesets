rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_196_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b8795a76869a3dc5532143e63d53cd40d58c6c5319daab2c836d4321ea8e38"

  strings:
    $s1 = "Lata(V4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}