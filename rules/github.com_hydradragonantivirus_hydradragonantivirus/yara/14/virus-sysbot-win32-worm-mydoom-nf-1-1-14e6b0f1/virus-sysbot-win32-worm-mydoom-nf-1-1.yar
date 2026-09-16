rule Virus_Sysbot_Win32_Worm_MyDoom_NF_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Worm.MyDoom.NF_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e8f0b3b84ba0fc83c2d9c42099f0dfcd50084d4e99868753193ca86ba7f06b"

  strings:
    $s1 = "&Serif" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}