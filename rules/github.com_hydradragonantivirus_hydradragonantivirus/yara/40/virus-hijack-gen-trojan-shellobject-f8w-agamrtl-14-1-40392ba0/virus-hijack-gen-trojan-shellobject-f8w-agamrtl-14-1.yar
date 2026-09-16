rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f2827379d4ec57994868e6bd88e6d30a7ed4aaa29c773b348ca7112f523b3a6"

  strings:
    $x1  = "<update><uicontrol><showwelcomedialog>y</><showinitialdialog>n</><showfinaldialog>n</><defaultworldregion>1</><showregisterdialo" ascii
    $s2  = "<update><uicontrol><showwelcomedialog>y</><showinitialdialog>n</><showfinaldialog>n</><defaultworldregion>1</><showregisterdialo" ascii
    $s3  = "Postponing update from " fullword ascii
    $s4  = " 99</><app11>Microsoft Bookshelf 99</><app12>Microsoft Bookshelf 99 ENG</><app13>Bibliorom Larousse (TM) 2.0</><app14>Lexirom 4." ascii
    $s5  = "0 - Edition 2000</><app15>Microsoft Picture It!</><app16>Encarta Encyclopedia</><app17>Microsoft" fullword ascii
    $s6  = "swa import export.x32" fullword ascii
    $s7  = "sound import export.x32" fullword ascii
    $s8  = " version mismatch. " fullword ascii
    $s9  = ", oldest compatible is " fullword ascii
    $s10 = "tiff import export.x32" fullword ascii
    $s11 = "sun au import export.x32" fullword ascii
    $s12 = "mpeg 3 import export.x32" fullword ascii
    $s13 = "targa import export.x32" fullword ascii
    $s14 = "lrg import export.x32" fullword ascii
    $s15 = "Flash install failed." fullword ascii
    $s16 = "png import export.x32" fullword ascii
    $s17 = " 1985-2006 Adobe Systems, Inc." fullword wide
    $s18 = " is a registered trademark and Shockwave(tm) is a trademark of Adobe Systems, Inc." fullword wide
    $s19 = "cursor asset.x32" fullword ascii
    $s20 = " World Atlas 2000</><app18>Microsoft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}