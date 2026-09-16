rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "468bed6b6f49e308c8006385187bc07858696068ade9fb287f30eb0b0d122ab7"

  strings:
    $s1 = "gIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}