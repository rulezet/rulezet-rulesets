rule Trojan_Danger_Win32_Jeefo_B_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Win32.Jeefo.B_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1d761faf2887455738eb7081bba8ec5750351f17684a21a9d541b30b9f7cbb8"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
    $x2  = "[FLog::Output] getCurrentVersion - opening read registry key component=%S" fullword ascii
    $s3  = "compiler: cl /Zi /Fdossl_static.pdb /MT /Zl /Gs0 /GF /Gy /W3 /wd4090 /nologo /O2 -Oy- -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_O" ascii
    $s4  = "[FLog::Output] setCurrentVersion - opening write registry key component=%S, version=%S, url=%S" fullword ascii
    $s5  = "void __thiscall crashpad::internal::ModuleSnapshotWin::GetCrashpadUserMinidumpStreams<struct crashpad::process_types::internal::" ascii
    $s6  = "[FLog::Output] ShellExecuteEx failed: %S" fullword ascii
    $s7  = "void __thiscall crashpad::internal::ModuleSnapshotWin::GetCrashpadUserMinidumpStreams<struct crashpad::process_types::internal::" ascii
    $s8  = "void __thiscall crashpad::internal::ModuleSnapshotWin::GetCrashpadUserMinidumpStreams<struct crashpad::process_types::internal::" ascii
    $s9  = "compiler: cl /Zi /Fdossl_static.pdb /MT /Zl /Gs0 /GF /Gy /W3 /wd4090 /nologo /O2 -Oy- -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_CPUID_O" ascii
    $s10 = "[FLog::Output] ShellExecuteEx succeeded" fullword ascii
    $s11 = "[DFLog::HttpTraceLight] HttpRequest(#%u %p) %s url:\"%s\" postSize:%zu cachePolicy:%d%s external:%d retry:%d%s" fullword ascii
    $s12 = "[FLog::Output] Starting install - force: %d, current version: %s, install version: %s" fullword ascii
    $s13 = "[FLog::Output] Failure getting '%s' from cdnHost='%s', falling back" fullword ascii
    $s14 = "[FLog::Output] httpWinInet requestId=%d Status: %u, ContentLength: %u" fullword ascii
    $s15 = "const void *__cdecl crashpad::GetSecurityDescriptorForNamedPipeInstance(unsigned int *)" fullword ascii
    $s16 = "bool __thiscall crashpad::ProcessSnapshotMinidump::InitializeModulesCrashpadInfo(class std::map<unsigned int,struct _MINIDUMP_LO" ascii
    $s17 = "[FLog::Output] BootstrapperClient::deployExtraStudioBootstrapper - Studio version = %S, url = %S" fullword ascii
    $s18 = "[FLog::Output] BootstrapperClient::deployExtraStudioBootstrapper - studio reg key open failed, error=0x%X" fullword ascii
    $s19 = "[FLog::Output] Bootstrapper::fetchInstalledEnvironments - failed to find installations key" fullword ascii
    $s20 = "[FLog::Output] BootstrapperClient::ProcessProtocolHandlerArgs - invalid launchmode" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}