rule Trojan_Danger_Trojan_GenericKD_72304918_95 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_95.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe61a8dc9586a05acd603a837f7f1628f0ee594d3e3536e4604b6524bf96fb8c"

  strings:
    $s1 = "SAip:<ElEK:D0" fullword ascii
    $s2 = "FrAP?1f" fullword ascii
    $s3 = "?NEXt!" fullword ascii
    $s4 = "A<cHug" fullword ascii
    $s5 = "Glop[+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}