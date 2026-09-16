rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_40_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_40_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1bf567d61d37292e500b32b296a2042500d638b742b74b8f7a8a3043443ae8"

  strings:
    $s1 = "TS@AXle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}