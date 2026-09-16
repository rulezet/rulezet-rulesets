rule Trojan_Hooker_Win32_Floxif_A_31 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7747e31a4910c38b3ee16567299b9b0f662a629cddaa7777b31655e95030aa73"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"2.4.0.0\" processorArch" ascii
    $s2  = "ependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" pro" ascii
    $s3  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"2.4.0.0\" processorArch" ascii
    $s4  = "Exec script: %s" fullword wide
    $s5  = "Dumping Scanner info->" fullword ascii
    $s6  = "User target folder: %s" fullword wide
    $s7  = "Executing done: %s" fullword ascii
    $s8  = "Error in CryptGetHashParam 0x%08x " fullword ascii
    $s9  = "Target folder: %s" fullword wide
    $s10 = " xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</ms_windowsSettings:dpiAware></windowsSettings></applicati" ascii
    $s11 = "Scan and Save-> Fallback -> scanning->" fullword wide
    $s12 = "/TEMP DNAME \"%s\" IP LOCAL" fullword wide
    $s13 = "Post:WM_RUNEVENT." fullword ascii
    $s14 = "Preparing scanning with Runner->" fullword ascii
    $s15 = "Expanding command line: %s" fullword wide
    $s16 = "Expanded command line: %s" fullword wide
    $s17 = "ScanToPDF -> Lower version" fullword wide
    $s18 = "ScanSmart: NW Status %d, USB Status %d, connType %d, connName %s" fullword wide
    $s19 = "Error in CryptImportKey 0x%08x " fullword ascii
    $s20 = "Error in CryptSetHashParam 0x%08x " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}