rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aiYvnz_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29e8a3ca82853f9328394a2a5dbc07ebc7b7a21fdfc746dac13250c079565113"

  strings:
    $s1  = "%s\\Temp%s%s update" fullword ascii
    $s2  = ".?AVCTWinService@WinNT@Common@TokyLibrary@@" fullword ascii
    $s3  = ".?AVCTIniFileReader@Util@Common@TokyLibrary@@" fullword ascii
    $s4  = ".?AV?$CTDeque@G@STL@Common@TokyLibrary@@" fullword ascii
    $s5  = "netsh advfirewall firewall delete rule name=\"%s\" program= %s" fullword ascii
    $s6  = "netsh firewall add allowedprogram \"%s\" \"%s\" ENABLE" fullword ascii
    $s7  = "Created by MIDL version 7.00.0500 at Thu Dec 04 01:19:37 2014" fullword ascii
    $s8  = "netsh advfirewall firewall add rule name=\"%s\" dir=in action=allow program=\"%s\"" fullword ascii
    $s9  = "netsh firewall delete allowedprogram \"%s\"" fullword ascii
    $s10 = ".?AVCTRegistry@WinNT@Common@TokyLibrary@@" fullword ascii
    $s11 = ".?AVCTString@Lang@Common@TokyLibrary@@" fullword ascii
    $s12 = ".?AV?$CTDeque@VCTString@Lang@Common@TokyLibrary@@@STL@Common@TokyLibrary@@" fullword ascii
    $s13 = "Remote%s" fullword ascii
    $s14 = ".?AVCTStringParser@Util@Common@TokyLibrary@@" fullword ascii
    $s15 = "PORT%d" fullword ascii
    $s16 = ">.  All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}