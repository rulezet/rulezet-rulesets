rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_amWqEpo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@amWqEpo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eda3dac83f989c4301440032a3b2dbd6b9518e58aaafeda58dc072f0f4f1554"

  strings:
    $s1 = "Print driver host for applications.exe" fullword wide
    $s2 = "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender Security Center\\Notifications' -Name DisableNotifications " wide
    $s3 = "Microsoft Help and Support" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}