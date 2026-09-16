rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_682_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_682_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f21e44ef71df09d322d95bdc52f83a8b836e6b1ea5e66873c56610aa75ef62b"

  strings:
    $x1 = "cmd /c reg add HKCU\\software\\microsoft\\windows\\currentversion\\run /v Backup /t REG_SZ /d D:\\Backup.exe /f" fullword wide
    $s2 = "The Hacker's Dictionary" fullword wide
    $s3 = " BACKSPACE " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}