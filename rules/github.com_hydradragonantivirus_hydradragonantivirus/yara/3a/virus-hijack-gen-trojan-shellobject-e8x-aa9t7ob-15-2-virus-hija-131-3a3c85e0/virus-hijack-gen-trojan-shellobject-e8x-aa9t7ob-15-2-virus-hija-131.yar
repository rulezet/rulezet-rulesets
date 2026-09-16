rule _Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_15_2_Virus_Hija_131 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_16_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_17_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfba14d619c1099cb92a2cf7689d922d563ec7e7159bc538ec0e61f8a5e6985e"
    hash2       = "49989f8fc7c4e3a2832291f8bb33021491f1fee24f61aec918a0794754f912ad"
    hash3       = "c708762aa3cfe520012d287b834c0f5bf771a8f78368dd8484dc86108fdaa401"
    hash4       = "0dc5de7cb1ea7b39c04751d1d7a39394a7ae67c01f2c26dd1f688044edb1ee9c"

  strings:
    $s1 = "schtasks.exe /Create /TN wininit /ru SYSTEM /SC ONSTART /TR \"" fullword ascii
    $s2 = "Your Computer Infected By Trojan (R) DiskWriter!!!" fullword wide
    $s3 = "HD(Part%d,Sig%08X)" fullword wide
    $s4 = "HD(Part%d,Sig%g)" fullword wide
    $s5 = "HD(Part%d,MBRType=%02x,SigType=%02x)" fullword wide
    $s6 = "Exception$]@" fullword ascii
    $s7 = "Uart(DEFAULT %c" fullword wide
    $s8 = "SPrint" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}