rule Virus_Hijack_Backdoor_Hangup_B_162_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43b40f44fddc7e03c86c3482a66dd9d4d1e230952d48eb59fea81fe32b6b4777"

  strings:
    $s1 = "Task Scheduler.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}