rule Virus_Hijack_Trojan_GenericKDZ_105924_213_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4392e2e8cd76f167e1b221784ab0b01753fa9f551fdb63ec2ced4aa2ba8b5522"

  strings:
    $s1 = "cd /d \"%~dp0bin\" && .\\bash --login -i" fullword ascii
    $s2 = "C:\\\\Program Files\\Windows Media Player\\wmpnscfg.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}