rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_183_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_183_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "804399563fb8293df4d32522fd33494a1410f7375ae2442e89bc3196ade654e9"

  strings:
    $s1 = "sANk*jn&Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}