rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_43_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_43_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29926ffc10b3317f17b31a895d82e8ee854524c6e159f048807c1a56bd95e1c7"

  strings:
    $x1  = "%AppName% attempted to perform an operation not allowed by the security policy. To grant this application the required permissio" wide
    $s2  = "%AppName% attempted to perform an operation not allowed by the security policy." fullword wide
    $s3  = "To grant this application the required permission, contact your system administrator, or use the Microsoft .NET Framework Config" wide
    $s4  = "ERR 2006: This template was not properly processed by SmartAssembly" fullword wide
    $s5  = "To help improve the software you use, %CompanyName% is interested in learning more about this error. We have created a report ab" wide
    $s6  = "If you want to be contacted by %CompanyName% regarding this error, please provide your e-mail address. This information will not" wide
    $s7  = "ERR 2005: The 128-bit encryption is not available on this computer. You need to install the High Encryption Pack in order to use" wide
    $s8  = "*** Information not reported for security reasons ***" fullword wide
    $s9  = "Ignore this error and attempt to &continue." fullword wide
    $s10 = "Please wait while %AppName% is sending the report to %CompanyName% through the Internet." fullword wide
    $s11 = "If you click Continue, the application will ignore this error and attempt to continue. If you click Quit, the application will c" wide
    $s12 = "You need to run {0} in full-trust, or at least grant it the UnmanagedCode security permission." fullword wide
    $s13 = "Please tell %CompanyName% about this problem." fullword wide
    $s14 = "Do you want to be contacted by %CompanyName% regarding this problem?" fullword wide
    $s15 = "THREAD RESUME FAILED" fullword wide
    $s16 = "Preparing the error report." fullword wide
    $s17 = "Failed to save the report." fullword wide
    $s18 = " Start /W \"\" \"" fullword wide
    $s19 = "%AppName% has encountered a problem." fullword wide
    $s20 = "SmartAssembly Exception Report|*.saencryptedreport|All files|*.*" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}