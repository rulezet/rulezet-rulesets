rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5ddf59077bde9978a7c69b80fe4a115e07b78b06d3a6d84269a9c98a69726f"

  strings:
    $s1 = "T'IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}