rule Trojan_Autorun_Gen_Trojan_Heur_D_cmHfbiFtCcj {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmHfbiFtCcj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65bc8c6e8020b26a8588b96ee8ce3709392eb06e3ae3734d07c507bf5df0d543"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}