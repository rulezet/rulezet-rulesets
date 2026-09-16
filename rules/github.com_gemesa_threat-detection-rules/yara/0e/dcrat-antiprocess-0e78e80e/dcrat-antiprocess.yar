rule DCRat_AntiProcess
{
    meta:
        description = "Detects DCRat anti-analysis process kill list."
        reference = "AntiProcess.cs"
        
    strings:
        $p1 = "Taskmgr.exe" ascii wide
        $p2 = "ProcessHacker.exe" ascii wide
        $p3 = "procexp.exe" ascii wide
        $p4 = "MSASCui.exe" ascii wide
        $p5 = "MsMpEng.exe" ascii wide
        $p6 = "MpUXSrv.exe" ascii wide
        $p7 = "MpCmdRun.exe" ascii wide
        $p8 = "NisSrv.exe" ascii wide
        $p9 = "ConfigSecurityPolicy.exe" ascii wide
        $p10 = "MSConfig.exe" ascii wide
        $p11 = "Regedit.exe" ascii wide
        $p12 = "UserAccountControlSettings.exe" ascii wide
        $p13 = "taskkill.exe" ascii wide

    condition:
        uint16(0) == 0x5A4D and 6 of ($p*)
}