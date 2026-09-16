rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7211962f76abcfe4f9c5397ce39e6ebebaca5ee998289cc074e56ed877051778"

  strings:
    $x1  = "C:\\Users\\tmc\\Documents\\Visual Studio 2015\\Projects\\WindowsServices\\svchost\\bin\\svchost.pdb" fullword ascii
    $x2  = "c:\\Users\\tmc\\Documents\\Visual Studio 2015\\Projects\\MicroBotMassiveNet\\taskhost\\obj\\x86\\Debug\\taskhost.pdb" fullword ascii
    $s3  = "Executes the Microsoft Task Host" fullword wide
    $s4  = "!Host Process for Windows Services" fullword ascii
    $s5  = "\\svchost.exe \"Microsoft Update Service\" ENABLE" fullword wide
    $s6  = "\\taskhost.exe \"Microsoft Update Helper\" ENABLE" fullword wide
    $s7  = "Attempt to bind an already bound trigger" fullword wide
    $s8  = "Microsoft Service Host" fullword wide
    $s9  = "\\Tor\\tor.exe \"Microsoft Update Installer\" ENABLE" fullword wide
    $s10 = "Microsoft Task Host" fullword wide
    $s11 = "Microsoft Tor Host" fullword wide
    $s12 = "firewall set service fileandprint disable" fullword wide
    $s13 = "Task Host" fullword wide
    $s14 = " \"Open TCP Port " fullword wide
    $s15 = "advfirewall firewall add rule name=\"Open TCP Port " fullword wide
    $s16 = " \"Open UDP Port " fullword wide
    $s17 = "advfirewall firewall add rule name=\"Open UDP Port " fullword wide
    $s18 = "Unsupported Priority Level" fullword wide
    $s19 = "Property Sheet failed to display" fullword wide
    $s20 = "TriggerList does not support Insert()." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}