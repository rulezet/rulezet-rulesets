rule Trojan_Hooker_Win32_Floxif_A_25 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95e836ad4050baad0c5083125481756360defc3380d6f371408f61b1cfc3bf24"

  strings:
    $s1 = "Copyright 1989. Hancom Inc. All rights reserved" fullword wide
    $s2 = "Setup is a registered trademark of Hancom Inc." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}