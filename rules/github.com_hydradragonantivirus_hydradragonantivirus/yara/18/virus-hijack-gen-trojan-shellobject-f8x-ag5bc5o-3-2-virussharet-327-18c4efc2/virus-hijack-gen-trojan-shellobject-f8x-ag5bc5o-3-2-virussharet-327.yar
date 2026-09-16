import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_3_2_VirusShareT_327 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_3_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "410b2670b93dc106e9f70d7b932f8c8291c1724fdc9de4177a7e0544015971cc"
    hash2       = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $x1  = "ftware\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HelpMe.exe\\RpcThreadPoolThrottle\"" fullword ascii
    $s2  = "  <name>@shell32.dll,-34575</name>" fullword ascii
    $s3  = "pSubKey->Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\"" fullword ascii
    $s4  = "      <description>@shell32.dll,-34577</description>" fullword ascii
    $s5  = "      <description>@shell32.dll,-34579</description>" fullword ascii
    $s6  = "<HTML><HEAD><STYLE>BODY {font-family: Tahoma;font-size: 10pt;color: 663c3c;margin-left: 25 px;margin-top: 25 px;background-posit" ascii
    $s7  = "ion: top left;background-repeat: repeat;}</STYLE></HEAD> <BODY background=\"ShadesOfBlue.jpg\"></BODY> </HTML> Bind" fullword ascii
    $s8  = "</libraryDescription>Bind" fullword ascii
    $s9  = "<HTML><HEAD><STYLE>BODY {font-family: Tahoma;font-size: 10pt;color: 663c3c;margin-left: 25 px;margin-top: 25 px;background-posit" ascii
    $s10 = "  <version>2</version>" fullword ascii
    $s11 = "  <isLibraryPinned>true</isLibraryPinned>" fullword ascii
    $s12 = "(null)\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "67533f79a87f4ce08c671dedbb7cb801" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}