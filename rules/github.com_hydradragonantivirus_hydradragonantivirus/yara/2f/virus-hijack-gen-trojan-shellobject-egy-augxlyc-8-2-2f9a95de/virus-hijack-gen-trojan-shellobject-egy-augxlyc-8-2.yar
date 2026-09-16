rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8b2cacb07f81d8e93b9d8d3112a208766a7bd84ec281daed31635b935a38a1"

  strings:
    $s1  = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2  = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3  = "Computer UTILITY" fullword wide
    $s4  = "Version 2.1" fullword wide
    $s5  = "Infinitely" fullword wide
    $s6  = "DAVT Corp." fullword wide
    $s7  = "mistic" fullword wide
    $s8  = "DAVT Utility" fullword wide
    $s9  = "Copyright 2014-2015 DAVT" fullword wide
    $s10 = "ClassED" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}