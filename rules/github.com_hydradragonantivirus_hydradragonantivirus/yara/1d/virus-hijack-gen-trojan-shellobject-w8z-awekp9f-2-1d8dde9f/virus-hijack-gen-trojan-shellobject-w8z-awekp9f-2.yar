rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aWEkp9f_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aWEkp9f_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a85f8f364195ea8cae9b6c29ad81fc51ffc8e7e225ca7c83ea18cdfdbcb382ae"

  strings:
    $s1 = "HoIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}