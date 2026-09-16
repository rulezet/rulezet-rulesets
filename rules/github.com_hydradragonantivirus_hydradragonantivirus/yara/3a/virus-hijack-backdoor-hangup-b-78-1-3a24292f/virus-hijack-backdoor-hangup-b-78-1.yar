rule Virus_Hijack_Backdoor_Hangup_B_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31f82d69a8d2c4ee3b64a1522c98e8d8623f83f86eaf3ad7242bfd84dc7e695c"

  strings:
    $x1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2  = "CLspInstall: EnumerateProviders LoadLibrary(ws2_32.dll) Fail" fullword wide
    $s3  = "Global\\WebPolicy Share Memory In MasterHelper.exe" fullword wide
    $s4  = "Global\\ProcProtect Share Memory In MasterHelper.exe" fullword wide
    $s5  = "InstallProviderVista: Unable to load ws2_32.dll!" fullword wide
    $s6  = "ProcHelper64.exe: Unable to load Winsock." fullword wide
    $s7  = "CFakeWebServer: send fail" fullword ascii
    $s8  = "CWebPolicyClient: PostPolicyMsg WideCharToMultiByte failed to convert" fullword wide
    $s9  = "* Build: 13367" fullword wide
    $s10 = "* Date: 2016/08/01 13:54:02" fullword wide
    $s11 = "* Free Build" fullword wide
    $s12 = "Global\\TopDomain WebPolicy ApplyPolicy ProcHelper64.exe Event" fullword wide
    $s13 = "RegCreateKey Fail,errCode is %d" fullword ascii
    $s14 = "InstallLsp: Unable to install the dummy LSP entry!." fullword wide
    $s15 = "ReorderCatalog: Reorder of 32-bit catalog failed: %d" fullword wide
    $s16 = "ReorderCatalog: Reorder of 64-bit catalog failed: %d" fullword wide
    $s17 = "RECV fail,err is %d" fullword ascii
    $s18 = "RegSetValueEx Fail,errCode is %d" fullword ascii
    $s19 = "Osama bin Mohammed bin Awad bin Laden" fullword wide
    $s20 = "CLspInstall: LspCreateHeap fail" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}