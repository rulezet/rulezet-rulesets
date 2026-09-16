rule Virus_Sysbot_Win32_Worm_MyDoom_NF_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Worm.MyDoom.NF_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04207151af5e15c41b7e20903adb07328a18ba5a2a612e2747ab525ae4bce806"

  strings:
    $s1 = "Tien Co Vun" fullword ascii
    $s2 = "Edit Short" fullword ascii
    $s3 = "Edit Long" fullword ascii
    $s4 = "Swap things" fullword ascii
    $s5 = "Edit Near" fullword ascii
    $s6 = "Old Editor" fullword ascii
    $s7 = "New track" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}