rule TRELLIX_ARC_Win_Netwalker_Reflective_Dll_Injection_Decoded: RANSOMWARE {
  meta:
    description  = "Rule to detect Reflective DLL Injection Powershell Script dropping Netwalker, after hexadecimal decoded and xor decrypted "
    author       = "McAfee ATR Team"
    id           = "9562c0b9-e7ac-5b96-99cc-1df91cb617af"
    date         = "2020-05-28"
    modified     = "2020-11-20"
    reference    = "https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/ | https://news.sophos.com/en-us/2020/05/27/netwalker-ransomware-tools-give-insight-into-threat-actor/"
    source_url   = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar#L77-L140"
    license_url  = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    hash         = "fd29001b8b635e6c51270788bab7af0bb5adba6917c278b93161cfc2bc7bd6ae"
    logic_hash   = "e99c045f39e7933e877a4df7793aa5ea6be5a782bb079419501929ba99844dec"
    score        = 75
    quality      = 30
    tags         = "RANSOMWARE"
    rule_version = "v1"
    malware_type = "ransomware"

  strings:
    $api0      = "[DllImport(\"kernel32.dll\",SetLastError = true, EntryPoint = \"VirtualAlloc\")]"
    $api1      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"GetProcAddress\")]"
    $api2      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"LoadLibraryA\")]"
    $api3      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"WriteProcessMemory\")]"
    $api4      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"VirtualFree\")]"
    $api5      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"GetCurrentProcess\")]"
    $api6      = "[DllImport(\"kernel32.dll\",SetLastError = true,EntryPoint = \"CloseHandle\")]"
    $api7      = "[DllImport(\"kernel32.dll\", SetLastError=true,EntryPoint = \"VirtualAllocEx\")]"
    $api8      = "[DllImport(\"kernel32.dll\", SetLastError=true,EntryPoint = \"VirtualProtectEx\")]"
    $api9      = "[DllImport(\"kernel32.dll\", SetLastError = true,EntryPoint = \"OpenProcess\")]"
    $api10     = "[DllImport(\"kernel32.dll\",EntryPoint = \"CreateRemoteThread\")]"
    $artifact0 = "[DllImport(\"kernel32.dll\",EntryPoint = \"CreateRemoteThread\")]"
    $artifact1 = "System.Runtime.InteropServices.Marshal]::PtrToStructure"
    $artifact2 = "System.Runtime.InteropServices.Marshal]::ReadInt16"
    $artifact3 = "env:WINDIR\\syswow64\\windowspowershell\\v1.0\\powershell.exe\" -NonInteractive -NoProfile -exec bypass"
    $artifact4 = "env:WINDIR\\syswow64\\windowspowershell\\v1.0\\powershell.exe\" -NonInteractive -NoProfile -exec bypass -file"
    $artifact5 = "[Parameter(Position = 0 , Mandatory"
    $artifact6 = "[Parameter(Position = 1 , Mandatory"
    $artifact7 = "-ExecutionPolicy ByPass -NoLogo -NonInteractive -NoProfile -NoExit"
    $artifact8 = "return [BitConverter]::ToInt64"

  condition:
    6 of ($api*) or ((3 of ($artifact*)))
}