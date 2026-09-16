rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2efb1d16e04835506580219b901cd8ea73332afc9ba3e752508fce63a5b47e6"

  strings:
    $s1 = "This assembly has been obfuscated with an evaluation version of DeepSea Obfuscator. Any commercial use and/or distribution of th" ascii
    $s2 = "This assembly has been obfuscated with an evaluation version of DeepSea Obfuscator. Any commercial use and/or distribution of th" ascii
    $s3 = "is assembly is prohibited!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}