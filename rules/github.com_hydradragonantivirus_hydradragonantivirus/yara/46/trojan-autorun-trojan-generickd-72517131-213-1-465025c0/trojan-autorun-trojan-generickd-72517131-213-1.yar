rule Trojan_Autorun_Trojan_GenericKD_72517131_213_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_213_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b41ad9956e7a8f79b227ca79acf8d774b12428ae67c5506346eb34a54de5cfab"

  strings:
    $s1 = "YUser, Marketing User, Manufacturing User, Purcha" fullword ascii
    $s2 = "FluE].2YLd#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}