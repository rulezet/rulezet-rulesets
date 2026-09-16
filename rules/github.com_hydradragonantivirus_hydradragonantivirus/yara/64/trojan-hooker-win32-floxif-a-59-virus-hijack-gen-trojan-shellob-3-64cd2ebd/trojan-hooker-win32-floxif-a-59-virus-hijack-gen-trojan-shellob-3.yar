import "pe"
rule _Trojan_Hooker_Win32_Floxif_A_59_Virus_Hijack_Gen_Trojan_ShellOb_3 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_59.vir, Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fcfb1f587eb49c172310b673f9bf2d7051a6e6c8d42556c81aafdb054bc9a9b"
    hash2       = "56070412a6e7209e9119d7402952a04ef8063fb535ed4ce8abed661594077a01"

  strings:
    $x1  = "If you would like to run antiviral software on download completion, you should type or browse the complete path to its executabl" ascii
    $s2  = "Man.exe process to exceptions according to antiviral software documentation, and set up antiviral checking on this dialog." fullword ascii
    $s3  = "(you should type square brackets as well). If no parameters are set, IDM will execute antiviral software appending the complete " ascii
    $s4  = "If you would like to run antiviral software on download completion, you should type or browse the complete path to its executabl" ascii
    $s5  = "Note that all modern antiviral software have \"real-time protection\" feature that checks all operations with files on your comp" ascii
    $s6  = "Also, in some cases, real time protection may significantly slow down the assembly of files made by IDM. Then you need to add ID" ascii
    $s7  = "(you should type square brackets as well). If no parameters are set, IDM will execute antiviral software appending the complete " ascii
    $s8  = " will have to set them manually in \"Command line parameters\" according to antiviral software documentation. The scanned file a" ascii
    $s9  = "Note that all modern antiviral software have \"real-time protection\" feature that checks all operations with files on your comp" ascii
    $s10 = "Unknown error during Connection::Connect()" fullword ascii
    $s11 = "er, and it includes all files downloaded in IDM. Thus, you need to add antiviral software scanner to IDM settings only when real" ascii
    $s12 = "Unknown error during SessionManager::CoverUpTheTraces()" fullword ascii
    $s13 = "IDM Status :)" fullword wide
    $s14 = "IDM has received \"Access Denied\" error while assembling file parts. It might happen because the file was opened by another app" ascii
    $s15 = "-time protection is turned off in antiviral software settings." fullword ascii
    $s16 = " 6.42 Build 5 (Mar/22/2024) " fullword ascii
    $s17 = "Copyright 2023 Tonec FZE. All rigths reserved." fullword wide
    $s18 = "IDM could not start Update application. This may be due to incorrect antiviral software settings for the folder containing IDM s" ascii
    $s19 = "cation like antiviral software, or you tried to open it yourself. In order to assemble this file, you will need to reboot your c" ascii
    $s20 = "IDM could not start Update application. This may be due to incorrect antiviral software settings for the folder containing IDM s" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "7b8d983565478bdc1ccabfea31fdb5f2" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}