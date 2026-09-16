import "pe"
rule _Virus_Infector_Win32_Sality_3_Virus_Infector_Win32_Sality_3_2_2 {
  meta:
    description = "datamaliciousorder - from files Virus.Infector_Win32.Sality.3.vir, Virus.Infector_Win32.Sality.3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2151d4eca5fb07279bc740e0dc9c31b45d933d2100b5ec115f838907a6708cb"
    hash2       = "d125e5841cc4146ad3e3f21d97a7a5176bf0fb65fac19a6642e9e014f1cbd7e4"

  strings:
    $s1 = "roSY}G&v" fullword ascii
    $s2 = "kUge<Ip" fullword ascii
    $s3 = "HAlf[l#" fullword ascii
    $s4 = "4!kATH" fullword ascii
    $s5 = "c]fOur" fullword ascii
    $s6 = "Ry$pOcK" fullword ascii
    $s7 = "{izLe[" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "dcbe94b8cc54b8e53867c61cc96811d6" and (all of them)
    ) or (all of them)
}