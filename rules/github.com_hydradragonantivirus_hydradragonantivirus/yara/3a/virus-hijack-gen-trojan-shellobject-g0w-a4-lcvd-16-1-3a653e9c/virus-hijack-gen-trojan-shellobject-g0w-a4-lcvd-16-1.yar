rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_a4_lcVd_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47579a1d73433180f1098dea681e309d153dd0252a0fb02e4e8af3caeea2fa2b"

  strings:
    $s1 = "tAuN)2;ni" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}