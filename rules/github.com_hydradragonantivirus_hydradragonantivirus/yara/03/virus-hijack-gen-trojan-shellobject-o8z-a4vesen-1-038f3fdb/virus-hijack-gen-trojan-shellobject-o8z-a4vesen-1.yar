rule Virus_Hijack_Gen_Trojan_ShellObject_o8Z_a4vesEn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.o8Z@a4vesEn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f469014bd35a2fa9dfdddeaae9528d507c84b22dd6129fab6e7aa1618e94d70d"

  strings:
    $s1 = "-!microsoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii
    $s2 = "THOUGH WE DO NOT, YOU CA NNOT RECOVER MORE THA N YOU PAI`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}