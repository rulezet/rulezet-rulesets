rule Trojan_Danger_Trojan_GenericKD_72677122_270_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_270_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1edf50f2b452d37c8d526d3262f2bcc54d1d5cc1eb71dd4012b7271b823f1306"

  strings:
    $s1  = "verso$o" fullword ascii
    $s2  = "BeAl?Hn" fullword ascii
    $s3  = "M\"Beer" fullword ascii
    $s4  = "5_F@DARE" fullword ascii
    $s5  = "5Dg kAPA" fullword ascii
    $s6  = "}kOkU&" fullword ascii
    $s7  = "dIRD *" fullword ascii
    $s8  = "B*lARI" fullword ascii
    $s9  = "Bora#," fullword ascii
    $s10 = "{}PIrl" fullword ascii
    $s11 = "S>mora" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}