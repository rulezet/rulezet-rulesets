rule Trojan_Autorun_Win32_Neshta_A_8 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee9a9371b1bf2de4681e68f586957e87212c0d7f1c9daad4b2d40307528ebb69"

  strings:
    $s1 = "Synaptics hardware installtaion commands: %s" fullword wide
    $s2 = "Copyright (C) Synaptics Incorporated 1996-2010" fullword wide
    $s3 = "Synaptics OEM setup" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}