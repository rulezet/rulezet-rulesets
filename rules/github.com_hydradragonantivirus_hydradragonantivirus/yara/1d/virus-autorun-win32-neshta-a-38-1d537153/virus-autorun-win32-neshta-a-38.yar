rule Virus_Autorun_Win32_Neshta_A_38 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_38.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7414315f673492cd0b12aab7327d628fd53dbd68c9ac0eb8ba0edaa4aad5378d"

  strings:
    $s1 = "PatchMgr.dll not found. Updates cannot be determined" fullword wide
    $s2 = "CMControlRes.dll not found. Updates cannot be determined" fullword wide
    $s3 = "CMControlRes.dll not found. Application not started." fullword wide
    $s4 = "Subscription Center" fullword wide
    $s5 = "Design Solutions Group1" fullword ascii
    $s6 = "BMicrosoft Sans Serif" fullword wide
    $s7 = "Copyright (c) 1982-2010 by Autodesk, Inc." fullword wide
    $s8 = "Communication Center" fullword wide
    $s9 = "CAD Manager Control Utility" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}