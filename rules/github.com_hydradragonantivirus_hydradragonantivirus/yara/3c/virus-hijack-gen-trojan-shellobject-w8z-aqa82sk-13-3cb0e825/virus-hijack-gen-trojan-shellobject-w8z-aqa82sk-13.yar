rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "833b6ff0cf9a9e7f044b4e1ec58c3b23a560dcdd7a28aa4b29b8c21e53437782"

  strings:
    $s1 = "{IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}