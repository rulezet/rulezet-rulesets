rule Trojan_Danger_Trojan_GenericKD_72677122_134_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de4e9a1ba10bf41d6ac7c171ead973cfec2dfc77c68cde8a2d74ff503d7e6354"

  strings:
    $s1 = "at,Jiti" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}