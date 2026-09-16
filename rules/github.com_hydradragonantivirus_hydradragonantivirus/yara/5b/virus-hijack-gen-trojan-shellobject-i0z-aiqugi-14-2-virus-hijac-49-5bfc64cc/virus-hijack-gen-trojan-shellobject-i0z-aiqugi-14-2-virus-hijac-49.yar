import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_14_2_Virus_Hijac_49 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6b7ffe1e72a2249d5f77279325b3983e2ec7a36cb5c437a128e468685c16118"
    hash2       = "1760f591bd3dc1476cd190a254b6141a1200939169be8139131a6cecb9548103"

  strings:
    $s1  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdminObject" fullword wide
    $s2  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\Scheduler" fullword wide
    $s3  = "/run /I /TN \"\\Microsoft\\Windows\\Windows Activation Technologies\\ValidationTask\"" fullword wide
    $s4  = "SYSTEM\\CurrentControlSet\\services\\eventlog\\Application\\WGA Scanner" fullword wide
    $s5  = "Windows Activation Technologies Service" fullword wide
    $s6  = "\\Microsoft\\Windows\\Windows Activation Technologies" fullword wide
    $s7  = "SOFTWARE\\Policies\\Microsoft\\Windows Activation Technologies" fullword wide
    $s8  = "Windows Activation Technologies" fullword wide
    $s9  = "Closes validation session started by OpenValidationSession" fullword ascii
    $s10 = "Opens validation session and obtains offline genuine status and blobWW0" fullword ascii
    $s11 = "Reports online validation result to Admin ObjectWW1" fullword ascii
    $s12 = "SESSION:" fullword wide
    $s13 = "SESSION:ReValidateTamperDays" fullword wide
    $s14 = "Wga Scanner" fullword wide
    $s15 = "Obtains property data managed by the Admin ObjectW:" fullword ascii
    $s16 = "WatAdminSvc Type LibraryWW" fullword ascii
    $s17 = "Microsoft Update KB971033" fullword wide
    $s18 = "SOFTWARE\\Microsoft\\Genuine Advantage" fullword wide
    $s19 = "Performs Windows 7 Validation" fullword wide
    $s20 = "WatAdminSvcObject Class" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "15e7b3b52439ffd4e161d95000d607a7" and (8 of them)
    ) or (all of them)
}