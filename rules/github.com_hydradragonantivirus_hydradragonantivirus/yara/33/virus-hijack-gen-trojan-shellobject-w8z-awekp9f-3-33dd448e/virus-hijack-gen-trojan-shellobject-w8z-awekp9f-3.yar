rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aWEkp9f_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aWEkp9f_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "057d586d9408c9ac15c0f53fad80282a19bce274f8e9f4dc483d9df093bda7fc"

  strings:
    $s1 = ";}IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}