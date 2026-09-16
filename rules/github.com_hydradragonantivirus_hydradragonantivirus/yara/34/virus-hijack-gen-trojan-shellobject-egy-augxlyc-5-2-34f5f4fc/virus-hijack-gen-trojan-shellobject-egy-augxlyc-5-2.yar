rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43fdadef3bfa3948665985ecbd4cdf1d68d9dcb7ddbaeb15ddf07a955e51d7bc"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "porrect" fullword ascii
    $s4 = "Open File Error." fullword ascii
    $s5 = "Landed company" fullword wide
    $s6 = "Version 1.1.16" fullword wide
    $s7 = "Click %u" fullword ascii
    $s8 = "Copyright by Landed" fullword wide
    $s9 = "Landed" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}