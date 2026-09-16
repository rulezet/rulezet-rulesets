rule Trojan_Hooker_Win32_Floxif_A_27 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7abf25ff084178968fff622f69ab8ead3d4c5b46361f3a254070e3d52751548"

  strings:
    $s1 = "Portions Copyright (C) 2000-2016 Martijn Laan" fullword ascii
    $s2 = "Inno Setup version 5.5.9 (a)" fullword ascii
    $s3 = "Setup version: Inno Setup version 5.5.9 (a)" fullword ascii
    $s4 = "Copyright (C) 1997-2016 Jordan Russell" fullword ascii
    $s5 = "Sorted<0A" fullword ascii
    $s6 = "Style<0A" fullword ascii
    $s7 = "State<0A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}