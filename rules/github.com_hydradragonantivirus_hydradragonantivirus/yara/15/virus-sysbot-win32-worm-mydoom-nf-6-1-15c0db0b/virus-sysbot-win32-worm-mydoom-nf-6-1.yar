rule Virus_Sysbot_Win32_Worm_MyDoom_NF_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Worm.MyDoom.NF_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f38d4348725837a860c81ade380e2d2fe209517554ec313cba45e88005c8f00c"

  strings:
    $s1 = "&Serif" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}