rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49232d3ec0ecf52e6e111163007931464bfcd1123dade844362389b684eac113"

  strings:
    $s1  = " - Copyright (c) 2005-2016 " fullword ascii
    $s2  = "SFX module - Copyright (c) 2005-2016 Oleg Scherbakov" fullword ascii
    $s3  = "7-Zip archiver - Copyright (c) 1999-2015 Igor Pavlov" fullword ascii
    $s4  = " 7-Zip - Copyright (c) 1999-2015 " fullword ascii
    $s5  = "The archive is corrupted, or invalid password was entered." fullword ascii
    $s6  = "7z SFX Constructor v4.5.0.0 (http://usbtor.ru/viewtopic.php?t=798)" fullword wide
    $s7  = ";Project created in program 7z SFX Constructor" fullword ascii
    $s8  = "1.7.0 develop [x86] build 3900 (April 1, 2016)" fullword ascii
    $s9  = "1.7.0 develop [x86] " fullword ascii
    $s10 = "DDINGXXPADDINGPADD;!@Install@!UTF-8!" fullword ascii
    $s11 = "Chuyu Team" fullword wide
    $s12 = " Chuyu. All rights reserved." fullword wide
    $s13 = ";yelK[a" fullword ascii
    $s14 = "&o!IChU" fullword ascii
    $s15 = "</assembly>PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}