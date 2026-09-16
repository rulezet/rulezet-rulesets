rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b5caf156f17893b52938beb4ef7ab6d378f44a0603a3c75dbfa76c2c43fe216"

  strings:
    $s1 = "T)GAWN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}