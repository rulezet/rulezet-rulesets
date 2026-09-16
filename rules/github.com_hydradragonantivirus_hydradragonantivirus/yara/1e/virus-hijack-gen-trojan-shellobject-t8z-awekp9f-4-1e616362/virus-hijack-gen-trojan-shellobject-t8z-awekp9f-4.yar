rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c774dbcdb19d10c8ba2fd25872e3bfb6a4303962a40c099ee0bc9ec9d0dbfa01"

  strings:
    $s1 = "b!IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}