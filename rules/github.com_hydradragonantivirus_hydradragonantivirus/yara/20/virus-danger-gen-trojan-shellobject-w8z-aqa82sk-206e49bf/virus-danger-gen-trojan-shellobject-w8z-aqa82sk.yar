rule Virus_Danger_Gen_Trojan_ShellObject_w8Z_aqA82Sk {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.w8Z@aqA82Sk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4fed112f13b63182390d8bb5cad35eef6b256ede715b469b82441213dc269d0"

  strings:
    $s1 = "QIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}