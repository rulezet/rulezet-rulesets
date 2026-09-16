rule Virus_Hijack_Backdoor_Hangup_B_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63e6f484744fabdefa8410805d13727e6aed952c834c41fc028c04a7f656e298"

  strings:
    $s1 = "acknowledge that you will create and activate an administrator account and password and that the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}