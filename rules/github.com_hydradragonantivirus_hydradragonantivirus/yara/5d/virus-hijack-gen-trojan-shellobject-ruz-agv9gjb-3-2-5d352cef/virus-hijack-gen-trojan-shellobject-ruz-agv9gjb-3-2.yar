rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c199fab787f408e6b48dff23bb2f4eed44959e92f26e4ff707af25ff06d556"

  strings:
    $s1  = "Target Compress Bad Pointer : 0x%08x, %d " fullword ascii
    $s2  = "$Header: n:\\development/speak_freely/GSM/GSM_CREA.C,v 1.1.1.1 1998/10/15 00:47:39 Administrator Exp $" fullword ascii
    $s3  = "Fail to Create Temporary File" fullword ascii
    $s4  = "Source Compress Bad Pointer : 0x%08x, %d " fullword ascii
    $s5  = "Fail to Compression" fullword ascii
    $s6  = "file not found - sound file" fullword ascii
    $s7  = "Fail to Compression !" fullword ascii
    $s8  = "Zlib Uncompression Error" fullword ascii
    $s9  = "Fail to Uncompression !" fullword ascii
    $s10 = "Effect%d.wav" fullword ascii
    $s11 = "Fail to Create File !" fullword ascii
    $s12 = "%s Player Ver. %d.%d" fullword ascii
    $s13 = "Compact Movie Ver. 2.0, Ser." fullword ascii
    $s14 = "Copyright 2000 Mirion Systems" fullword wide
    $s15 = " => AVERAGE" fullword ascii
    $s16 = " (Full Screen)" fullword ascii
    $s17 = "SemE?=" fullword ascii
    $s18 = "FIfo)," fullword ascii
    $s19 = "%s Player" fullword ascii
    $s20 = "q!SOYa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}