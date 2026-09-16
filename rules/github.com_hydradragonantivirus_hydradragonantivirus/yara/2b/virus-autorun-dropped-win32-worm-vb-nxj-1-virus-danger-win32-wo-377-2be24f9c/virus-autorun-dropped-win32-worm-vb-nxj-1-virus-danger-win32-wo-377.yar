rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_1_Virus_Danger_Win32_Wo_377 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash2       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash3       = "0ddd2c9145afaab6ae9d694619759a4d6569ae9345c64061e81160a1d2b93def"

  strings:
    $s1  = "Add/Remove Programs PropertiesqYou do not have administrator privileges on this computer.  Please have the administrator uninsta" wide
    $s2  = "ERROR: \"%s\" doesn't exist." fullword wide
    $s3  = "Important MSN Explorer Information.htm" fullword ascii
    $s4  = "MSN Setup is already running." fullword wide
    $s5  = "Uninstall has detected that MSN Explorer is running." fullword wide
    $s6  = "Uninstall is complete.uYou must restart your computer before the new settings will take effect." fullword wide
    $s7  = "Note: For information about how to connect to the Internet or use your e-mail, please open \"Important MSN Explorer Information" wide
    $s8  = "Uninstall is complete." fullword wide
    $s9  = "Uninstalling MSN Explorer will not cancel your account with your Internet Service Provider.  However, if you signed up for dial-" wide
    $s10 = "HTML Application Host Window Class" fullword ascii
    $s11 = "MSN Explorer Uninstall" fullword wide
    $s12 = "Do you want to uninstall MSN Explorer?" fullword wide
    $s13 = "Click OK to have Uninstall close it for you." fullword wide
    $s14 = "Please wait while MSN Explorer Uninstall prepares to run..." fullword wide
    $s15 = "Click Cancel to close it yourself." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}