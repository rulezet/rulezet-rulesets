rule Trojan_Autorun_Gen_Trojan_Heur_D_cmHfbGeK0bf {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Heur.D.cmHfbGeK0bf.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b35d17dacb0774ae21b2b7b9f3e447b506a698a3a79249c1671ff1b326ab542"

  strings:
    $s1 = "(char)('" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}