rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_Virus_Hijack_Gen_Trojan_127 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b79a57a926f801baca06e13180644ff8a9531494ec2bc0fb219ba35b9e51f5"
    hash2       = "6490cc176e7cb13652619da0d9c31fd3d02759c398e4f8467f919339d8fa1415"
    hash3       = "8bb24d7147c7f8b0ceb987045095bf8e35e1876cb028a6fe705e72802b3ab17c"
    hash4       = "0ddd2c9145afaab6ae9d694619759a4d6569ae9345c64061e81160a1d2b93def"

  strings:
    $s1  = "temporary internet files" fullword wide
    $s2  = "Playlist Contents Modified" fullword wide
    $s3  = "WMPL Playlist Contents Modified Event Message String" fullword wide
    $s4  = "Groveling Completed" fullword wide
    $s5  = "WMPL Groveling Completed Event Message String" fullword wide
    $s6  = "WMPL Search Completed Event Message String" fullword wide
    $s7  = "Copyright (C) 1992-2001 Microsoft Corporation" fullword wide
    $s8  = "Refetch CD Metadata" fullword wide
    $s9  = "Object NAme Modified" fullword wide
    $s10 = "Library Client Resync Requested" fullword wide
    $s11 = "Object Unmarked for Deletion" fullword wide
    $s12 = "Object Marked for Deletion" fullword wide
    $s13 = "Child Removed from Object" fullword wide
    $s14 = "Child Added to Object" fullword wide
    $s15 = "Groveled Media Found" fullword wide
    $s16 = "Groveling Progress" fullword wide
    $s17 = "Groveling Started" fullword wide
    $s18 = "Library Emptied" fullword wide
    $s19 = "Object Found" fullword wide
    $s20 = "Object Modified" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}