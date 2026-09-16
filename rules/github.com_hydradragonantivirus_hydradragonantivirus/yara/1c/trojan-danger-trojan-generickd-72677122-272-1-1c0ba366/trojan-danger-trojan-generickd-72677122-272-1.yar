rule Trojan_Danger_Trojan_GenericKD_72677122_272_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_272_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa0216eeaa1df47c4e1a7d61effb3ff380f2cbf5fbcc4c8d8b335f440f762932"

  strings:
    $s1  = "?instance@EregConfiguration@@SAPAV1@XZ" fullword ascii
    $s2  = "?close@EregConfiguration@@SAXXZ" fullword ascii
    $s3  = "?instance@AdlmConfiguration@@SAPAV1@XZ" fullword ascii
    $s4  = "?close@SimpleConfiguration@@SAXXZ" fullword ascii
    $s5  = "?close@CdaConfiguration@@SAXXZ" fullword ascii
    $s6  = "?close@FlmConfiguration@@SAXXZ" fullword ascii
    $s7  = "?instance@SimpleConfiguration@@SAPAV1@XZ" fullword ascii
    $s8  = "?close@AdlmConfiguration@@SAXXZ" fullword ascii
    $s9  = "?instance@FlmConfiguration@@SAPAV1@XZ" fullword ascii
    $s10 = "?instance@CdaConfiguration@@SAPAV1@XZ" fullword ascii
    $s11 = "AAutodesk Network Licensing Service" fullword wide
    $s12 = "Error: Unexpected error (%ld)" fullword wide
    $s13 = "Student Version" fullword wide
    $s14 = "Not For Resale Version" fullword wide
    $s15 = "Copyright (c) 1999-2007 Macrovision Corporation" fullword wide
    $s16 = "Autodesk Copyright (C) 2008" fullword wide
    $s17 = " $Revision: 1.2 $ .\\src\\a479.c" fullword ascii
    $s18 = " $Revision: 1.2 $ .\\src\\a482.c" fullword ascii
    $s19 = " $Revision: 1.5 $ .\\src\\a324.c" fullword ascii
    $s20 = " $Revision: 1.3 $ .\\src\\a253.c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}