rule _Trojan_Danger_Trojan_Agent_EICV_1_Trojan_Sysbot_Trojan_Agent_EI_293 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.Agent.EICV_1.vir, Trojan.Sysbot_Trojan.Agent.EICV.vir, Trojan.Sysbot_Trojan.GenericKD.46147426.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_582_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca71e035c3398ec3084caac20f764a171bed9b00985973911d9fa67eafefcf28"
    hash2       = "a8119f30045fa35980ae0ca4e39053f512f56078a5a0a8b20cc2e96247fb446d"
    hash3       = "263456e9a50d7005b5ea1ff87ffaf00d0a2c70d1b6451b2b2d27edce3246667d"
    hash4       = "504922aa72650134be58ed6e9e081f8440e6f23f1f96e27425ee791c1f65dc09"

  strings:
    $s1  = "schtasks.exe /Change /TN \"\\Microsoft\\Office\\Office Feature Updates Logon\" /Disable /ru \"\"" fullword ascii
    $s2  = "schtasks.exe /Change /TN \"\\Microsoft\\Office\\Office ClickToRun Service Monitor\" /Disable /ru \"\"" fullword ascii
    $s3  = "schtasks.exe /Change /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\KernelCeipTask\" /Disable /ru \"\"" fullword ascii
    $s4  = "echo \"\" > C:\\ProgramData\\Microsoft\\Diagnosis\\ETLLogs\\AutoLogger\\AutoLogger-Diagtrack-Listener.etl" fullword ascii
    $s5  = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\Lmhosts\" /v Start /t REG_DWORD /d 4 /f" fullword ascii
    $s6  = "schtasks.exe /Change /TN \"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" /Disable /ru \"\"" fullword ascii
    $s7  = "schtasks.exe /Change /TN \"\\Microsoft\\Office\\Office Automatic Updates 2.0\" /Disable /ru \"\"" fullword ascii
    $s8  = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\WinHttpAutoProxySvc\" /v Start /t REG_DWORD /d 4 /f" fullword ascii
    $s9  = "schtasks.exe /Change /TN \"\\Microsoft\\Office\\Office Feature Updates\" /Disable /ru \"\"" fullword ascii
    $s10 = "schtasks.exe /Change /TN \"\\Microsoft\\Windows\\Windows Media Sharing\\UpdateLibrary\" /Disable /ru \"\"" fullword ascii
    $s11 = "schtasks.exe /Change /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip\" /Disable /ru \"\"" fullword ascii
    $s12 = "schtasks.exe /Change /TN \"\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\" /Disable /ru \"\"" fullword ascii
    $s13 = "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\" /v AUTO /t REG_SZ /d 0 /f" fullword ascii
    $s14 = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\services\\FDResPup\" /v Start /t REG_DWORD /d 4 /f" fullword ascii
    $s15 = "sc config dmwappushservice start= disabled" fullword ascii
    $s16 = "REM disable passive probing" fullword ascii
    $s17 = "sc config \"ClickToRunSvc\" start= disabled" fullword ascii
    $s18 = "sc delete dmwappushservice" fullword ascii
    $s19 = "sc stop dmwappushservice" fullword ascii
    $s20 = "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\Main\" /V \"Start Page\" /D \"\" /F" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}