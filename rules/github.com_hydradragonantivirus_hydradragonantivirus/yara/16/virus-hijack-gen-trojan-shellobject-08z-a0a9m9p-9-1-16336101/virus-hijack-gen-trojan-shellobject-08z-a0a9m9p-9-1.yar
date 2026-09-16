rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cac0c7d94c19a5be134d2931f902d1b78d227bae22235491eadbfb7f417a373"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"PDF24 Creator\" processorA" ascii
    $s2  = "t-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecuti" ascii
    $s3  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity name=\"PDF24 Creator\" processorA" ascii
    $s4  = "cture=\"*\" version=\"1.0.0.0\" type=\"win32\"></assemblyIdentity><description>PDF24 Creator</description><dependency><dependent" ascii
    $s5  = "Could not create temporary file '%s'" fullword wide
    $s6  = "f:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
    $s7  = " xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
    $s8  = "Could not create named pipe handler thread." fullword wide
    $s9  = "Temporary files folder could not be created" fullword ascii
    $s10 = "Temporary files folder not writeable" fullword wide
    $s11 = "/C net start pdf24 && pause" fullword wide
    $s12 = "Could not create temporary files folder" fullword wide
    $s13 = "Could not create named pipe: %s" fullword wide
    $s14 = "Failed to stop service" fullword wide
    $s15 = "The following temporary files folder does not exist and could not be created by the current user. Please ensure that PDF24 can c" wide
    $s16 = "The following temporary files folder is not writeable by the current user. Please ensure that PDF24 can write into that folder b" wide
    $s17 = "ZString::getAt(int): Index out of range" fullword ascii
    $s18 = "type not supported for toDouble" fullword ascii
    $s19 = "Port in Url invalid" fullword ascii
    $s20 = "type not supported for toInt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}