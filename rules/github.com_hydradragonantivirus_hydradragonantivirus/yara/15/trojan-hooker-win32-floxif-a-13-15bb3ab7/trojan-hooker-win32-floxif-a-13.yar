rule Trojan_Hooker_Win32_Floxif_A_13 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "303a3620ddf17d23cc15655e85e66f3e0a2d81a5dd1678f1155daf254cf16d5e"

  strings:
    $s1  = "<description>FastStone Screen Focus</description>" fullword ascii
    $s2  = "\"%1%\" already exists." fullword wide
    $s3  = "FastStone Corporation" fullword wide
    $s4  = "Copyright (C) 2021 by FastStone Corporation" fullword wide
    $s5  = "Visible,uA" fullword ascii
    $s6  = "Grouped(" fullword ascii
    $s7  = "Screen Focus" fullword ascii
    $s8  = "Width,uA" fullword ascii
    $s9  = "Indent`" fullword ascii
    $s10 = "Interval,uA" fullword ascii
    $s11 = "Masked,uA" fullword ascii
    $s12 = "FastStone Screen Focus" fullword wide
    $s13 = "Alt +/- : Size   Shift +/- : Dim   Esc : Close" fullword wide
    $s14 = "   Shift +/- : " fullword wide
    $s15 = "!'%s' is not a valid integer value\"'%s' is not a valid currency value!'%g' is not a valid date and timeInvalid argument to tim" wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}