rule Trojan_Danger_Trojan_GenericKD_72677122_194_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6e4e66068fb86a566172dc2195cb99458a26007898a54a8de542b0b953728f0"

  strings:
    $s1  = ".\\Depend\\dhconfigsdk.libEC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\MFC\\LIB\\mfc42.libFC:\\Program Files (x86)" ascii
    $s2  = "Microsoft Visual Studio\\VC98\\LIB\\kernel32.libBC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\user32.libAC:\\Pro" ascii
    $s3  = "mctl32.lib@C:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\uuid.libBC:\\Program Files (x86)\\Microsoft Visual Studi" ascii
    $s4  = "CMicrosoft (R) 32-bit C/C++ Optimizing Compiler Version 12.00.9782.0" fullword ascii
    $s5  = "bCC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\shell32.libDC:\\Program Files (x86)\\Microsoft Visual Studio\\VC9" ascii
    $s6  = ".\\Depend\\dhconfigsdk.libEC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\MFC\\LIB\\mfc42.libFC:\\Program Files (x86)" ascii
    $s7  = "s (x86)\\Microsoft Visual Studio\\VC98\\LIB\\gdi32.libDC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\comdlg32.lib" ascii
    $s8  = "\"operator struct IConnectionPoint *" fullword ascii
    $s9  = "operator struct HKEY__ *" fullword ascii
    $s10 = "operator struct IErrorInfo *" fullword ascii
    $s11 = "\"operator struct ICreateErrorInfo *" fullword ascii
    $s12 = "al Studio\\VC98\\LIB\\urlmon.libCC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\msvcprt.libDC:\\Program Files (x86" ascii
    $s13 = "VC98\\LIB\\olepro32.libDC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\oleaut32.libBC:\\Program Files (x86)\\Micro" ascii
    $s14 = "LIB\\oledlg.libAC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\ole32.libDC:\\Program Files (x86)\\Microsoft Visual" ascii
    $s15 = "Visual Studio\\VC98\\MFC\\LIB\\mfcs42.libBC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\msvcrt.libDC:\\Program Fi" ascii
    $s16 = "am Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\winspool.libDC:\\Program Files (x86)\\Microsoft Visual Studio\\VC98\\LIB\\ad" ascii
    $s17 = "!?Create@CDialog@@QAEHIPAVCWnd@@@Z6" fullword ascii
    $s18 = ")__imp_?Create@CDialog@@QAEHPBDPAVCWnd@@@Z\"" fullword ascii
    $s19 = "operator struct IRegistrar *" fullword ascii
    $s20 = "operator struct ITypeLib *" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}