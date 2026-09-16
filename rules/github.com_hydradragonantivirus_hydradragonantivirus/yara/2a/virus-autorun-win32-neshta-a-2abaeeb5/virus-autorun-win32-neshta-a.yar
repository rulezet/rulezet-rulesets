rule Virus_Autorun_Win32_Neshta_A {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6030c7ffd9cd25e29942d781cab1d35cb2f1ef3bdc07f3c7d1b33efbfc66a32"

  strings:
    $s1  = "Portions Copyright (C) 2000-2021 Martijn Laan" fullword wide
    $s2  = "Comparer`oJ" fullword ascii
    $s3  = "Comparer(xH" fullword ascii
    $s4  = "System,GE" fullword ascii
    $s5  = "Comparer,Wc" fullword ascii
    $s6  = "System<cL" fullword ascii
    $s7  = "Comparer,(c" fullword ascii
    $s8  = "System<Af" fullword ascii
    $s9  = "System ^I" fullword ascii
    $s10 = "Comparer$\"g" fullword ascii
    $s11 = "System<hM" fullword ascii
    $s12 = "Setup version: Inno Setup version 6.2.0" fullword wide
    $s13 = "Inno Setup version 6.2.0" fullword wide
    $s14 = "Handle ^I" fullword ascii
    $s15 = "Visible`GE" fullword ascii
    $s16 = "Count$Mf" fullword ascii
    $s17 = "Count`?H" fullword ascii
    $s18 = "+Inno Setup Messages (6.0.0) (u)" fullword ascii
    $s19 = "List$%G" fullword ascii
    $s20 = "Count$#]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}