rule Trojan_Hooker_Win32_Floxif_A_8 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "025a307289fe69b9f4bf2f98678fa2a70ebeb50ffaaa6c359d219401754bd5cb"

  strings:
    $x1  = "G:\\Users\\cc4build\\Documents\\Visual Studio 2010\\Work\\Application\\ControlCenter\\ControlCenter4\\Product\\Develop\\ControlC" ascii
    $s2  = "The function failed. - OpenTargetAppList" fullword wide
    $s3  = "G:\\Users\\cc4build\\Documents\\Visual Studio 2010\\Work\\Application\\ControlCenter\\ControlCenter4\\Product\\Develop\\ControlC" ascii
    $s4  = "The function failed. - OpenUxSysInfo" fullword wide
    $s5  = "The function failed. - OpenMainProcInfo" fullword wide
    $s6  = "The function failed. - OpenBootInfo" fullword wide
    $s7  = "  <description>Brother ControlCenter UX System</description>" fullword ascii
    $s8  = "Command line parameter = %s" fullword wide
    $s9  = "Already running CC UX-System." fullword wide
    $s10 = "ControlCenter UX System" fullword wide
    $s11 = "Brother ControlCenter" fullword wide
    $s12 = "    name=\"Brother ControlCenter UX System\"" fullword ascii
    $s13 = "Illegal start procedure." fullword wide
    $s14 = "NO TEXT!" fullword wide
    $s15 = "Index Sheet" fullword wide
    $s16 = "Copyright(C) 2009-2014 Brother Industries, Ltd." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}