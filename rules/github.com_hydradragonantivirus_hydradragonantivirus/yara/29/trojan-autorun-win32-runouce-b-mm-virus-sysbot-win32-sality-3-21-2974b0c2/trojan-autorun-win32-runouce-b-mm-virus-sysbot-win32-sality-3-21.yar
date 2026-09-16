rule _Trojan_Autorun_Win32_Runouce_B_mm_Virus_Sysbot_Win32_Sality_3_21 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Win32.Runouce.B@mm.vir, Virus.Sysbot_Win32.Sality.3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e2b27b6ae78f24e07ba3f5efc3334909169fc387deca9370e0920e446d39eac"
    hash2       = "3770b4f5b74c4e382078cef59f521642bbec4ce2590d89ca86ae0a88e3a05544"

  strings:
    $s1  = "[%s(%d)] Install version dir is exits:%s" fullword wide
    $s2  = "Range: bytes=%s-" fullword wide
    $s3  = "?GetMenuCheckInfo@MenuObserverImpl@DuiLib@@UBEPAV?$map@VCDuiString@DuiLib@@_NU?$less@VCDuiString@DuiLib@@@std@@V?$allocator@U?$p" ascii
    $s4  = "?GetSelectItems@CListUI@DuiLib@@QAE?AV?$vector@PAVCControlUI@DuiLib@@V?$allocator@PAVCControlUI@DuiLib@@@std@@@std@@XZ" fullword ascii
    $s5  = "?GetMenuCheckInfo@MenuObserverImpl@DuiLib@@UBEPAV?$map@VCDuiString@DuiLib@@_NU?$less@VCDuiString@DuiLib@@@std@@V?$allocator@U?$p" ascii
    $s6  = "pair@$$CBVCDuiString@DuiLib@@_N@std@@@4@@std@@@Z" fullword ascii
    $s7  = "?Expand@CVirtualTreeDataSource@DuiLib@@QAEXPAVCVirtualTreeNodeDataBase@2@@Z" fullword ascii
    $s8  = "?Select@CVirtualListDataBase@DuiLib@@UAEX_N@Z" fullword ascii
    $s9  = "200 PORT" fullword wide
    $s10 = "?SetMenuCheckInfo@MenuObserverImpl@DuiLib@@UAEXPAV?$map@VCDuiString@DuiLib@@_NU?$less@VCDuiString@DuiLib@@@std@@V?$allocator@U?$" ascii
    $s11 = "?UnScale@CDPI@DuiLib@@QAEHH@Z" fullword ascii
    $s12 = "?Init@CMenuWnd@DuiLib@@QAEXPAVCMenuElementUI@2@VSTRINGorID@2@UtagPOINT@@PAVCPaintManagerUI@2@PAV?$map@VCDuiString@DuiLib@@_NU?$l" ascii
    $s13 = "?CreateMenu@CMenuWnd@DuiLib@@SAPAV12@PAVCMenuElementUI@2@VSTRINGorID@2@UtagPOINT@@PAVCPaintManagerUI@2@PAV?$map@VCDuiString@DuiL" ascii
    $s14 = "?Scale@CDPI@DuiLib@@QAEXPAUtagRECT@@_N@Z" fullword ascii
    $s15 = "ib@@_NU?$less@VCDuiString@DuiLib@@@std@@V?$allocator@U?$pair@$$CBVCDuiString@DuiLib@@_N@std@@@4@@std@@KPAUtagRECT@@@Z" fullword ascii
    $s16 = "?Scale@CDPI@DuiLib@@QAEHH_N@Z" fullword ascii
    $s17 = "ess@VCDuiString@DuiLib@@@std@@V?$allocator@U?$pair@$$CBVCDuiString@DuiLib@@_N@std@@@4@@std@@KPAUtagRECT@@@Z" fullword ascii
    $s18 = "?SetMenuCheckInfo@MenuObserverImpl@DuiLib@@UAEXPAV?$map@VCDuiString@DuiLib@@_NU?$less@VCDuiString@DuiLib@@@std@@V?$allocator@U?$" ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}