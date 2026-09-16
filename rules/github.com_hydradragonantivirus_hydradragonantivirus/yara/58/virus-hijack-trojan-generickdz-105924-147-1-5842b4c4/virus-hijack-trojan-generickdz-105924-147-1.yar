rule Virus_Hijack_Trojan_GenericKDZ_105924_147_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea95110c6eace17e1362e51ea50327a99899b76c7295650363325a22bf70a05b"

  strings:
    $s1 = "server, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" fullword wide
    $s2 = "schtasks /run /TN Update" fullword wide
    $s3 = "Type)Microsoft.Win32.TaskScheduler.IdleTriggerY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}