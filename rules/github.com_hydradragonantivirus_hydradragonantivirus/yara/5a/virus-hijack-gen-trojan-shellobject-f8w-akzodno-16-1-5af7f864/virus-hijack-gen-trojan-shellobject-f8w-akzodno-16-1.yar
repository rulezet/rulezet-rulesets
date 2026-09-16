rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6eb9f59cfba355da52fd95f612b617c9875acc0a60759600e0b78cf5d987467d"

  strings:
    $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security>    <requestedPrivileges>     <requestedExecutionLevel  level=\"" ascii
    $s3 = "erms of the GNU General Public License as published by the Free Software Foundation; either v" fullword wide
    $s4 = "insert name" fullword ascii
    $s5 = "rogram is free software; you can redistribute it and/or modify it under the " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}