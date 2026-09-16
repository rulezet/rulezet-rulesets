import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_106_1_Trojan_Danger_Tro_266 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_106_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_107_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_108_1.vir, Virus.Autorun_Gen.Heur.Mint.Zard.39.vir, Virus.Autorun_Gen.Heur.Mint.Zard.39_1.vir, Virus.Autorun_Gen.Heur.Mint.Zard.39_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e444d2d09c98794052ed35d7179b23b11707ac89e5370c86345bdb784721f93e"
    hash2       = "a8ec1be9b89b43fcd1f4219c5ef81b29b7e8d0bae5fdf5c65a9195a8da3faf62"
    hash3       = "56a1efbfb1b39ad5e48da6da21448cb40803752ee6d2ed3c1b5c399c653a210b"
    hash4       = "e50505902a8b1fdcd59bba527361701d9c5744119adbc15afe031c60948f9903"
    hash5       = "7a2e4c49adf05cb8e2b1afcf316a207c4cda0a4388fe937aa46c1ecfed47eeeb"
    hash6       = "e46997cb6a5db994426214c78fc25955035311e5ce7bb0ac4a958d3b44524989"

  strings:
    $x1  = "Dumping processes }" fullword ascii
    $x2  = "Dumping processes {" fullword ascii
    $s3  = "Spread finished, dumping spreads" fullword ascii
    $s4  = "Dumping string vector" fullword ascii
    $s5  = "Startup loader [%s], hostid [%s]" fullword ascii
    $s6  = "Mutex owned, creating loader object" fullword ascii
    $s7  = "FileInfo dump {" fullword ascii
    $s8  = "Wait user process" fullword ascii
    $s9  = "Installed soft dump }" fullword ascii
    $s10 = "Installed soft dump {" fullword ascii
    $s11 = "CreateProcess [%s] success" fullword ascii
    $s12 = "New process [%s][%s]" fullword ascii
    $s13 = "Copy ourself and start: %s, commandline %s" fullword ascii
    $s14 = " Download started. Content length %d" fullword ascii
    $s15 = " process monitor" fullword ascii
    $s16 = "CMultiLoader::Work unknown exception (step %d)" fullword ascii
    $s17 = "CMultiLoader::Work exception: %s (step %d)" fullword ascii
    $s18 = "Can't get process name, wait another process" fullword ascii
    $s19 = " InternetSetFilePointer OK, already downloaded %d byte(s)" fullword ascii
    $s20 = "Client's process resumed" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3eafac78b2f94eb6a014af9c2a27809" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}