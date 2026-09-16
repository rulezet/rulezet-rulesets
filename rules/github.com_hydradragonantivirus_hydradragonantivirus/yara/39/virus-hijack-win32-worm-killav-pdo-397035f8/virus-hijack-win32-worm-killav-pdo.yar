rule Virus_Hijack_Win32_Worm_Killav_PDO {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Win32.Worm.Killav.PDO.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c73accc365abe185cea6ead54427d10efd0d9783303d42332d67f438ec9f397e"

  strings:
    $s1 = " /e /p everyone:f" fullword ascii
    $s2 = "start lanmanworkstation" fullword ascii
    $s3 = "start lanmanserver" fullword ascii
    $s4 = "start Browser" fullword ascii
    $s5 = "(C) 360.cn Inc. All Rights Reserved." fullword wide
    $s6 = "SHERRY" fullword ascii
    $s7 = "Task:L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}