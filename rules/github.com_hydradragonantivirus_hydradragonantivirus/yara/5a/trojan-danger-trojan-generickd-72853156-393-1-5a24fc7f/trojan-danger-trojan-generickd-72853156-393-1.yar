rule Trojan_Danger_Trojan_GenericKD_72853156_393_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_393_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93a9053183a7472ab5d1fcd9f1df27f4c9ae5e51b35d8ed551bf3cea8fb9523a"

  strings:
    $s1 = "<embed autoplay=\"true\" src=\"sound.mp3\"  width=\"1\" height=\"1\" />" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}