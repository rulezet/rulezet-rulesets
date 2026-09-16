rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_22_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "827f4169763e317f822a1e8355df97b2d9a9b5cd26716077d470ca54594d73b5"

  strings:
    $s1  = "you represent is a Content Management System or .NET component vendor, you may not purchase a" fullword wide
    $s2  = "Content Management System and/or .NET component vendors are not allowed to use the Software" fullword wide
    $s3  = "BEFORE ATTEMPTING TO DOWNLOAD OR USE ANY SOFTWARE, DOCUMENTATION, OR OTHER" fullword wide
    $s4  = "Bunifu Framework - UI Lib" fullword wide
    $s5  = "(as defined below) without the express permission of Bunifu Technologies Ltd. If you or the company" fullword wide
    $s6  = "Downloading file:" fullword wide
    $s7  = "Was not able to download file!" fullword wide
    $s8  = "Download finished!" fullword wide
    $s9  = " PLEASE READ THIS END USER LICENSE AGREEMENT (THE " fullword wide
    $s10 = "WHICH YOU REPRESENT AND ARE AUTHORIZED TO BIND (the " fullword wide
    $s11 = "AND/OR BY PURCHASING, DOWNLOADING, INSTALLING OR OTHERWISE USING THE SOFTWARE" fullword wide
    $s12 = "HAVE THE POWER AND AUTHORITY TO BIND THAT COMPANY." fullword wide
    $s13 = "2007 Microsoft Office System User" fullword wide
    $s14 = "Http Job already running." fullword wide
    $s15 = "license for or use the Software unless you contact Bunifu Technologies Ltd. directly and obtain" fullword wide
    $s16 = "This License does not grant You a license or any rights to the " fullword wide
    $s17 = "Software not expressly granted to You as part of the License hereunder are reserved in all respects by" fullword wide
    $s18 = "unclick" fullword ascii
    $s19 = "Custom Bunifu .NET controls" fullword wide
    $s20 = "IMPORTANT " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}