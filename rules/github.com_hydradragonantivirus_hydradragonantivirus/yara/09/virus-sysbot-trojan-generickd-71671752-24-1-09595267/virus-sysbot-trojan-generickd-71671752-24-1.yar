rule Virus_Sysbot_Trojan_GenericKD_71671752_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b236e247ff87867e04f5ebd4f2932e545fdd6aa40e65c2bc57836986441aa6b"

  strings:
    $s1 = "YAlE?~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}