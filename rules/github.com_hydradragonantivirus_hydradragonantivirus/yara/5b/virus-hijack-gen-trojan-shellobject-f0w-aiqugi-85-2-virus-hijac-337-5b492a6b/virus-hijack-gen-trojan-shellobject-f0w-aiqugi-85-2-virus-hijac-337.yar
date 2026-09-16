rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_85_2_Virus_Hijac_337 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash2       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash3       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash4       = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash5       = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash6       = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash7       = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash8       = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash9       = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash10      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash11      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"
    hash12      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash13      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash14      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"

  strings:
    $s1  = "   -p          Optional password for remote login. If you don't present" fullword ascii
    $s2  = "   -u          Optional user name for remote login." fullword ascii
    $s3  = "   -x          Show processes, memory information and threads." fullword ascii
    $s4  = "   -t          Show process tree." fullword ascii
    $s5  = "   -e          Exact match the process name." fullword ascii
    $s6  = "firewall ports allow RPC access, and your account has read access the following key on the remote system:" fullword ascii
    $s7  = "Make sure that the Remote Registry service is running on the remote system, that you have" fullword ascii
    $s8  = "   pid         Show information about specified process." fullword ascii
    $s9  = "   -s [n]      Run in task-manager mode, for optional seconds specified." fullword ascii
    $s10 = "   name        Show information about processes that begin with the name" fullword ascii
    $s11 = "   -d          Show thread detail." fullword ascii
    $s12 = "   -m          Show memory detail." fullword ascii
    $s13 = "   -r n        Task-manager mode refresh rate in seconds (default is 1)." fullword ascii
    $s14 = "               on the command line pslist will prompt you for it if necessary." fullword ascii
    $s15 = "   \\\\computer  Specifies remote computer." fullword ascii
    $s16 = "   -nobanner   Do not display the startup banner and copyright message." fullword ascii
    $s17 = "   Priv Pk     Private Virtual Memory Peak" fullword ascii
    $s18 = "   Thd         Number of Threads" fullword ascii
    $s19 = "   Priv        Private Virtual Memory" fullword ascii
    $s20 = "   Cswtch      Context Switches" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}