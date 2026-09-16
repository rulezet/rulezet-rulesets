rule Virus_Autorun_Win32_Neshta_A_17 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9594279e6e9c6292a15473459f0e1c19ecedc50cf0525930db9bfed07f336359"

  strings:
    $s1 = " Windows(TM) Operating System" fullword ascii
    $s2 = "(c) Copyright Microsoft Corp. 1993. All rights reserved." fullword ascii
    $s3 = "Copyright (C) Microsoft Corp 1991.  All rights reserved." fullword ascii
    $s4 = "Non-Windows application font for 386 enhanced mode (USA code page 437)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}