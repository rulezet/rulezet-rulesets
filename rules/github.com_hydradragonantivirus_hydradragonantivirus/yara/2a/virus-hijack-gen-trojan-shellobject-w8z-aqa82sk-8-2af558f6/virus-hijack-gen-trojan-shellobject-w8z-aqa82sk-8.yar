rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49410cbd436ce84fc13f69f93d20729b757149dd37498ddafb8ae37747a2e352"

  strings:
    $s1 = "K~IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}