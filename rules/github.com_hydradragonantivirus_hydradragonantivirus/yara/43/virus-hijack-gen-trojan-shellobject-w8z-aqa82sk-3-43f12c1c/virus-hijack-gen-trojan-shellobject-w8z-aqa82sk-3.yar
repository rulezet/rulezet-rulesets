rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96eca0a426ad7495c7da8e944c0fb54fe8d41222e5491818ad733646363c2c79"

  strings:
    $s1 = "<%IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}