import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_225_1_Trojan_Danger_Tro_146 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_225_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_226_1.vir, Virus.Infector_Generic.Malware.SFPfVo!dld!Pk!12g.CB8AEA47.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb211b5180d2ef814429863ebd2da6c6e5f63356a3529457f3057a8cc42a7d8b"
    hash2       = "fa192c41da38b9f2bec3af2aaeb26945303bb4d0ee12a42a9674a3f2f4593011"
    hash3       = "eb8ae63bb541e96802277cd4aecf2de4757cf7801868fc3c21d9f195ff4bc453"

  strings:
    $x1  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe" fullword ascii
    $s2  = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Your Image File Name Here without a path" fullword ascii
    $s3  = "process killer" fullword ascii
    $s4  = "Winsock error - Winsock initialization failed" fullword ascii
    $s5  = "Winsock error - Socket creation Failed!" fullword ascii
    $s6  = "Zone Alarm Mutex" fullword ascii
    $s7  = "Failed to resolve hostname." fullword ascii
    $s8  = "Microsoft(R) Windows(R) 2000 Operating System" fullword wide
    $s9  = "anti spy" fullword ascii
    $s10 = "Failed to establish connection with server" fullword ascii
    $s11 = "protection scan" fullword ascii
    $s12 = "scan for vir" fullword ascii
    $s13 = "ETHEREAL" fullword ascii
    $s14 = "LOOKOUT" fullword ascii
    $s15 = "luke file" fullword ascii
    $s16 = "resource hack" fullword ascii
    $s17 = "trend micro" fullword ascii
    $s18 = "visual basi" fullword ascii
    $s19 = "anti repla" fullword ascii
    $s20 = "registry monitor" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5afda5bec5ddd3ba31023406f0fca220" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}