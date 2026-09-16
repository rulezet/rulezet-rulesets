import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqsS8zj_11_2_Virus_Infe_204 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_11_2.vir, Virus.Infector_Win32.Worm.VB.NUD.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47c1718b0c5f2799c130ee6113633091dbccd9d7a36590736a0a85378bf4aa48"
    hash2       = "1c8779d2186910be9cb1929ec92b00b6679b72c6c94790f98cf6d6be41736084"

  strings:
    $x1  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ProcessManager.exe\\Debugger" fullword wide
    $x2  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rundll32.exe\\Debugger" fullword wide
    $x3  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msconfig.exe\\Debugger" fullword wide
    $x4  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ctfmon.exe\\Debugger" fullword wide
    $x5  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\\Debugger" fullword wide
    $x6  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\boot.exe\\Debugger" fullword wide
    $x7  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autorun.exe\\Debugger" fullword wide
    $x8  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autoruns.exe\\Debugger" fullword wide
    $x9  = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\auto.exe\\Debugger" fullword wide
    $x10 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procexp.exe\\Debugger" fullword wide
    $x11 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MSACCESS.exe\\Debugger" fullword wide
    $x12 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WINWORD.exe\\Debugger" fullword wide
    $x13 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\POWERPNT.exe\\Debugger" fullword wide
    $x14 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\EXCEL.exe\\Debugger" fullword wide
    $x15 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MSPUB.exe\\Debugger" fullword wide
    $x16 = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Photoshop.exe\\Debugger" fullword wide
    $s17 = "If Not fs.fileexists(\"C:\\WINDOWS\\pchealth\\helpctr\\binaries\\HelpHost.com\") Then fs.copyfile (\"C:\\WINDOWS\\Help\\microsof" ascii
    $s18 = "If Not fs.fileexists(\"C:\\WINDOWS\\pchealth\\helpctr\\binaries\\HelpHost.com\") Then fs.copyfile (\"C:\\WINDOWS\\Help\\microsof" ascii
    $s19 = "If Not fs.fileexists(\"C:\\WINDOWS\\system32\\dllcache\\Default.exe\") Then fs.copyfile (\"C:\\WINDOWS\\Help\\microsoft.hlp\"), " ascii
    $s20 = "If Not fs.fileexists(\"C:\\WINDOWS\\system32\\dllcache\\Default.exe\") Then fs.copyfile (\"C:\\WINDOWS\\Help\\microsoft.hlp\"), " ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "3274dc16fb06c92a0119b94734d01456" and (1 of ($x*) and all of them)
    ) or (all of them)
}