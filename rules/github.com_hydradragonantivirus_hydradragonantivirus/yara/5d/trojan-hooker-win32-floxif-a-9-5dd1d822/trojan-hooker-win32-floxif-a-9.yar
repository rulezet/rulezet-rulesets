rule Trojan_Hooker_Win32_Floxif_A_9 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2d6495a2bd39b019d43d3a13b9c18fd90e0f931c5b1e958d62e5172a4d010d9"

  strings:
    $s1 = "A build of the PortableApps.com Launcher for VLC Media Player Portable, allowing it to be run from a removable drive.  For addit" wide
    $s2 = "VLC Media Player Portable (PortableApps.com Launcher)" fullword wide
    $s3 = "level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsof" ascii
    $s4 = "contact@rareideas.com0" fullword ascii
    $s5 = "VLC Media Player Portable" fullword wide
    $s6 = ":compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011457-1546-43" ascii
    $s7 = "350 Fifth Ave Suite 52091" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}