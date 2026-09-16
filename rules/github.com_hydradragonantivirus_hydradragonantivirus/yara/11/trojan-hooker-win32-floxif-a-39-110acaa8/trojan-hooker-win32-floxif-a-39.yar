rule Trojan_Hooker_Win32_Floxif_A_39 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d564b0c526474969be4f56a0794243591b5ccac0539e461cd2eb506105a015e"

  strings:
    $s1 = "Bootstrap Studio.exe" fullword wide
    $s2 = "level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schemas-microsof" ascii
    $s3 = "Bootstrap Studio 6.1.2 Portable (by xetrin)" fullword wide
    $s4 = ":compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011457-1546-43" ascii
    $s5 = "Bootstrap Studio" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}