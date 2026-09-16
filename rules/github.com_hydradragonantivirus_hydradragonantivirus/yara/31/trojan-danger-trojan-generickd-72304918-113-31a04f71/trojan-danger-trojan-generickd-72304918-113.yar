rule Trojan_Danger_Trojan_GenericKD_72304918_113 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_113.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f68cedd4990b4c41ad6e75e5095199f17c2d362eec05b3acc0804ad37d8fafd"

  strings:
    $s1 = "Start Command Prompt with Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}