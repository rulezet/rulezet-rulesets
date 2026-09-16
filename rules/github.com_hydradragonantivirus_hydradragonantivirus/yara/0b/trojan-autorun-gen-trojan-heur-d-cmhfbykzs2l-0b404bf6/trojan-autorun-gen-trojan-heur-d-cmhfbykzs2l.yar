rule Trojan_Autorun_Gen_Trojan_Heur_D_cmHfbykzS2l {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmHfbykzS2l.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe59f65a4c912fe37fb9c2758cffbdd92c8228d6905e951f6da29858a6816e6b"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}