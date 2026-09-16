rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e17efaf93dd750522a3781df5cd54110804fd9fb9b3ea48183e6167912931fe"

  strings:
    $s1 = "]7IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}