rule Trojan_Sysbot_Win32_Sality_3_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Win32.Sality.3_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7317bf2c195f1a0079d767049fdad4a2ad60c161c58300a7f330a78b9a919ee8"

  strings:
    $s1 = "[PostBuild] InstallHandler Done" fullword ascii
    $s2 = "[PostBuild] End Program" fullword ascii
    $s3 = "[PostBuild] UnInstallHandler Done" fullword ascii
    $s4 = "[PostBuild] PatchHandler Done" fullword ascii
    $s5 = "CyberLink Corp" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}