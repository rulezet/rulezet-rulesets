import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_15_1_Virus_Hija_174 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash2       = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash3       = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $x1  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|ArchiveDirectory|CaptureClipboard|DriverName|PipeMonitoringConfig|HashAlgorit" wide
    $x2  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|ArchiveDirectory|CaptureClipboard|DriverName|CopyOnDelete_PE|CopyOnDelete_SID" wide
    $x3  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|HashAlgorithms|DriverName|ArchiveDirectory|CopyOnDelete_Processes|CopyOnDelet" wide
    $x4  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|HashAlgorithms|DriverName|ArchiveDirectory|CopyOnDelete_Processes|CopyOnDelet" wide
    $x5  = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|HashAlgorithms|DriverName|ArchiveDirectory|CopyOnDelete_Processes|CopyOnDelet" wide
    $s6  = "\\pard\\sb120\\sa120\\b0\\fs19 These license terms are an agreement between Sysinternals (a wholly owned subsidiary of Microsoft" ascii
    $s7  = "\\pard\\sb120\\sa120\\b0\\fs19 These license terms are an agreement between Sysinternals (a wholly owned subsidiary of Microsoft" ascii
    $s8  = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Opti" fullword wide
    $s9  = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which incl" fullword ascii
    $s10 = "oration) and you.  Please read them.  They apply to the software you are downloading from Systinternals.com, which includes" fullword ascii
    $s11 = "Microsoft .Net Frameworak COMr+ Suppost" fullword ascii
    $s12 = "<!DOCTYPE Sysmon [<!ELEMENT Sysmon (EventFiltering|HashAlgorithms|DriverName|ArchiveDirectory|CopyOnDelete_Processes|CopyOnDelet" wide
    $s13 = "* claims for breach of contract, breach of war" fullword wide
    $s14 = "[CheckVCx64Runtime] : Setup could not find Microsoft Visual C++ 2013 (x64) run" fullword wide
    $s15 = "ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut modifier. La " wide
    $s16 = "ces and support services that you use, are the entire agreement for the software and supp" fullword ascii
    $s17 = "\\fs20 11.\\tab\\fs19 Disclaimer of Warranty.\\caps0    \\caps The software is licensed \"as - is.\"  You bear the risk of using" ascii
    $s18 = "es of merchant" fullword ascii
    $s19 = "\\pard\\sb120\\sa120 Elle s'applique \\'e9galement, m\\'eame si Sysinternals connaissait ou devrait conna\\'eetre l'\\'e9ventual" ascii
    $s20 = "\\pard\\fi-357\\li357\\sb120\\sa120\\tx360\\b\\fs20 3.\\tab SENSITIVE INFORMATI" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5f690c4d941183227dddce566546b357" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}