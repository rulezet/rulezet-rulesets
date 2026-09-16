rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a76b3fc2708eb5b44ba4a67b4abd430d30a78e1f5d3baf5929d55956cc67056"

  strings:
    $s1 = "L?tAAr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}