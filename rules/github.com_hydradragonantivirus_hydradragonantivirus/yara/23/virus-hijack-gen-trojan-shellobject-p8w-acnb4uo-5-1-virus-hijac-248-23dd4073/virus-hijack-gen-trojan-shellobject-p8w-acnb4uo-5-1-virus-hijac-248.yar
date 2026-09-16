import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_p8W_aCNb4Uo_5_1_Virus_Hijac_248 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash2       = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|ArchiveDirectory|CaptureClipboard|DriverName|PipeMonitoringConfig|HashAlgorit" wide
    $s2  = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATION. \\b0  Please be aware that, similar to other " ascii
    $s3  = "Processor signature: %08X" fullword wide
    $s4  = "Supports Control Flow Enforcement Technology" fullword wide
    $s5  = "Kernel CET" fullword wide
    $s6  = "\\pard\\fi-363\\li720\\sb120\\sa120\\'b7\\tab reverse engineer, decompi" fullword ascii
    $s7  = "iable or other sensitive information (such as usernames" fullword ascii
    $s8  = "Querying CET support requires admin rights" fullword wide
    $s9  = "User CET" fullword wide
    $s10 = "for this software, unless other terms accompany those items.If so," fullword wide
    $s11 = "Component C" fullword wide
    $s12 = "\\pard\\keepn\\sb120\\sa120\\b LIMITATION DES DOMMAGES" fullword ascii
    $s13 = "n-style:solid;text-decoration-c" fullword ascii
    $s14 = "Administrator rights are required to query information." fullword wide
    $s15 = "Child Object" fullword wide
    $s16 = "me si Sysinternals connaissait ou devrait conn" fullword wide
    $s17 = "SYSINTERNALS SOFTWARE LICENSE TE" fullword wide
    $s18 = "Outside the United States.If you acquired the software in any o" fullword wide
    $s19 = "United States.If you acquired the softwa" fullword wide
    $s20 = "Maximum implemented address width: %lu bits (virtual), %lu bits (physical)." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "55fe2519db5cc8102e98db551ca473a5" and (8 of them)
    ) or (all of them)
}