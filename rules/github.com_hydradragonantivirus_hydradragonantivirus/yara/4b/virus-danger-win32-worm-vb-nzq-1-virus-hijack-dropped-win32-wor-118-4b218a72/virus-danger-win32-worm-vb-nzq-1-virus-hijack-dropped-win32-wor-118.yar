rule _Virus_Danger_Win32_Worm_VB_NZQ_1_Virus_Hijack_Dropped_Win32_Wor_118 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash2       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"

  strings:
    $s1  = "Please go to http://www.microsoft.com/windows/ie/ and install the latest version of Internet Explorer.AWe were unable to load a " wide
    $s2  = "This will permanently remove your bookmarks, saved passwords, cookies and customizations. You may wish to keep this information " ascii
    $s3  = "EXECUTE ADD " fullword ascii
    $s4  = "A newer version of Internet Explorer is required to run MSN than the one currently installed on your computer." fullword wide
    $s5  = "This will permanently remove your bookmarks, saved passwords, cookies and customizations. You may wish to keep this information " ascii
    $s6  = " delivers safe, easy web browsing. A familiar user interface, enhanced security features including protection from online identi" ascii
    $s7  = "MSN Explorer - Not signed in" fullword wide
    $s8  = "You may not have the necessary permissions to use all the features of the program you are about to run. You may run this program" ascii
    $s9  = " as a different user or continue to run the program as the current user." fullword ascii
    $s10 = "Run the program as the &following user:" fullword ascii
    $s11 = "&Current user (%s)" fullword ascii
    $s12 = "MSN Explorer Error Reporting" fullword wide
    $s13 = "Error code: 0x%08x@We were unable to load procedure %s from %s." fullword wide
    $s14 = "Error code: 0x%08xGWe were unable to load procedure number %d from %s." fullword wide
    $s15 = "method failed" fullword ascii
    $s16 = "Uninstall Log Folder" fullword ascii
    $s17 = "if you plan on installing another version of " fullword ascii
    $s18 = "ty theft, and integrated search let you get the most out of the web." fullword ascii
    $s19 = " delivers safe, easy web browsing. A familiar user interface, enhanced security features including protection from online identi" ascii
    $s20 = "A restart of your computer may be required to complete the uninstall." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}