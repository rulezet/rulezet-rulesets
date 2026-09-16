rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92a4ded8ce7ba8e9f5c0f14031e33672e24f7d0a6e36ca8fdaa4d74fea6044a3"

  strings:
    $s1 = "server, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword wide
    $s2 = "schtasks /run /TN Update" fullword wide
    $s3 = "Type)Microsoft.Win32.TaskScheduler.TimeTriggerY" fullword ascii
    $s4 = "Type)Microsoft.Win32.TaskScheduler.IdleTrigger]" fullword ascii
    $s5 = "Type)Microsoft.Win32.TaskScheduler.BootTrigger_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}