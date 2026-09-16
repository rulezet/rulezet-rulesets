rule Virus_Danger_Trojan_GenericKDZ_103285_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "380ea456db7db8beaddfa8df165e1f8c717f13ef53797d2b03a25080a47f1b74"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}