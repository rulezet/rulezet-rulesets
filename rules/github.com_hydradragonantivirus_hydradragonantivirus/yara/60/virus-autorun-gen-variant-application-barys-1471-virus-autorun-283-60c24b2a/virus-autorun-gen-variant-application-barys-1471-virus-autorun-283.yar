rule _Virus_Autorun_Gen_Variant_Application_Barys_1471_Virus_Autorun__283 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash2       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash3       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash4       = "ed76141284fb07fe8c33040d0b95b54c78bbf494dfac4c802d2913d2c549d8f8"
    hash5       = "5617567edb85b034f48a9d1a05e6aacfdb9229c2044ab6e21c5784715176fbcc"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
    $s2  = "     i - don't inject ConEmuHk into starting process" fullword wide
    $s3  = "  Example: dir -new_console:bh9999c:d:\"C:\\\":P:\"^<PowerShell^>\" c:\\Users /s" fullword wide
    $s4  = "Usage: ConEmuC [switches] -ROOT <program with arguments, far.exe for example>" fullword wide
    $s5  = "   or: ConEmuC -download [-login <name> -password <pwd>]" fullword wide
    $s6  = "     -IsAdmin        - returns 1 as errorlevel if current user has elevated privileges, 2 if not" fullword wide
    $s7  = " prefix for Unix-path conversion, m:\"\" - no prefix" fullword wide
    $s8  = "               [-proxy <address:port> [-proxylogin <name> -proxypassword <pwd>]]" fullword wide
    $s9  = "       -CONPID=<PID> - 'soft' mode, don't inject ConEmuHk into <PID>" fullword wide
    $s10 = "     I - (GuiMacro only) forces inheriting of root process contents, like \"Duplicate root\"" fullword wide
    $s11 = "       -PID=<PID>    - use <PID> as root process" fullword wide
    $s12 = "     a - RunAs shell verb (as Admin on Vista+, user/pwd in Win2k and WinXP)" fullword wide
    $s13 = "     L:\"<dir>\\\" - the directory for ANSI log files" fullword wide
    $s14 = "     L:\"<logfile>\" - the full path for ANSI log file" fullword wide
    $s15 = "     R - force start hooks server in the parent process" fullword wide
    $s16 = "     u - ConEmu choose user dialog" fullword wide
    $s17 = "   or: ConEmuC [-SILENT] [-USEEXPORT] -GUIMACRO[:PID|HWND][:T<tab>][:S<split>] <GuiMacro command>" fullword wide
    $s18 = "     u:\"<user>:<pwd>\" - specify user/pwd in args" fullword wide
    $s19 = "Inject ConEmuHk" fullword wide
    $s20 = "       -TRMPID=<PID> - called from *.vshost.exe when 'AllocConsole' just created" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}