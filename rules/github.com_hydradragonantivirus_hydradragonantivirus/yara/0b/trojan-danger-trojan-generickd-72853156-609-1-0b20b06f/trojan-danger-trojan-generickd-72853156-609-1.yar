rule Trojan_Danger_Trojan_GenericKD_72853156_609_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_609_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c28035189252ec991b242f81f002cd214b18757ce6e812b3e1d4e85b8e20a736"

  strings:
    $s1 = "PSNR NTP Host Company" fullword wide
    $s2 = "PSNR NTP Space Provider" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}