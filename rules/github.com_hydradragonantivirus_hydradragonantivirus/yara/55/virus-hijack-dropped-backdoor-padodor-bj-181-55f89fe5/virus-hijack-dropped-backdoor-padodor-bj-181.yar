rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_181 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_181.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0497cdb0a9f895351c329b160f702b181898ae9f07c968f1db22081003093472"

  strings:
    $s1 = "dAdA#Cv" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}