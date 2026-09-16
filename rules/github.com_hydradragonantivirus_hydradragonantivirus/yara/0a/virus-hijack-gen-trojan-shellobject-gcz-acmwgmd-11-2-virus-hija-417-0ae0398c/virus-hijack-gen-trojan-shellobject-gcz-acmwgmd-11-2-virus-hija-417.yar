rule _Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_11_2_Virus_Hija_417 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_11_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_238_1.vir, Virus.Hooker_Trojan.VB.Agent.AWT_1.vir, Virus.Hooker_Win32.Ramnit.N_1.vir, VirusShareTrojanDownLoader1219594_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb45773aa5e78f9b74bc79aa13ab09f385809eba4b5c44714e9a1bf62684595"
    hash2       = "38d57b02dd6a282748156e58d28a30953228acd71fa035f3b81414ba058074fb"
    hash3       = "6d614471691193440e0326fd127d26c31ddc5b830f82a8df693c3178ec5692a6"
    hash4       = "4b0e91f435ebc6fcf8b35f71c7081e88093bff24ab27c2c4b4dcb920bd6a5a07"
    hash5       = "45a66a58046646b91234288d52958a064e416be85ba5ac11639c0c5ea991bdf1"

  strings:
    $s1  = "Failed to load logexts.dll" fullword ascii
    $s2  = "Failed to initialize logexts.dll" fullword ascii
    $s3  = "[WinMain] Couldn't load logexts.dll 0x%x" fullword ascii
    $s4  = "[DebuggerLoop] process spawned. BaseImage: 0x%x StartAddress: 0x%x" fullword ascii
    $s5  = "[InitLogexts] logexts.dll not available." fullword ascii
    $s6  = "[WinMain] logexts.dll loaded" fullword ascii
    $s7  = "[DebuggerLoop] DLL UNLOADED. BaseDll: 0x%X \"%s\"." fullword ascii
    $s8  = "[DebuggerLoop] DLL LOADED. BaseDll: 0x%X \"%s\"." fullword ascii
    $s9  = "[WinMain] Failed to create the UI thread." fullword ascii
    $s10 = "[DebuggerLoop] DLL LOADED. BaseDll: 0x%X cannot get the name." fullword ascii
    $s11 = "[DebuggerLoop] new thread. StartAddress: 0x%x" fullword ascii
    $s12 = "[DebuggerLoop] DLL UNLOADED. BaseDll: 0x%X unknown." fullword ascii
    $s13 = "Win32 API Logging Utility" fullword wide
    $s14 = "[DebuggerLoop] Hit single step breakpoint." fullword ascii
    $s15 = "[DebuggerLoop] What is this ?" fullword ascii
    $s16 = "[DebuggerLoop] Hit initial breakpoint." fullword ascii
    $s17 = "This will kill the debuggee. Do you want to exit ?" fullword ascii
    $s18 = "[DebuggerLoop] Not handled on IA64." fullword ascii
    $s19 = "&Flush the buffer" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}