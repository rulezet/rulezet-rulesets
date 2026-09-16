rule Trojan_Autorun_Win32_Neshta_A_6 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23dd75cf89f47716069fbbdfa12b6cca30be521417e82d509ab487d87111f022"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.1.0\" processorArch" ascii
    $s2  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.1.0\" processorArch" ascii
    $s3  = "ft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requ" ascii
    $s4  = " file execute error" fullword wide
    $s5  = "Execute file name: " fullword ascii
    $s6  = "Execute param: " fullword ascii
    $s7  = "ExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSett" ascii
    $s8  = " Execute file path: " fullword wide
    $s9  = "+Installing the driver/software, please wait&Does not support this Operating System" fullword wide
    $s10 = " file execute success" fullword wide
    $s11 = "Does not support this Operating System: " fullword ascii
    $s12 = "Can't find AsusSetup64.exe" fullword ascii
    $s13 = "gs><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application><ms_" ascii
    $s14 = "^c:\\program files (x86)\\microsoft visual studio\\2017\\professional\\vc\\tools\\msvc\\14.16.27023\\atlmfc\\include\\afxwin1.in" wide
    $s15 = " Install failed: The current driver in system is better." fullword wide
    $s16 = "Installation failedOSystem needs to reboot to complete the installation. Do you want to reboot now?" fullword wide
    $s17 = "GetOSVersion fail" fullword ascii
    $s18 = "GetMessage error" fullword ascii
    $s19 = "GetProcAddress failed. Last Error is %d" fullword wide
    $s20 = "System needs to reboot to complete the installation. Do you want to reboot now?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}