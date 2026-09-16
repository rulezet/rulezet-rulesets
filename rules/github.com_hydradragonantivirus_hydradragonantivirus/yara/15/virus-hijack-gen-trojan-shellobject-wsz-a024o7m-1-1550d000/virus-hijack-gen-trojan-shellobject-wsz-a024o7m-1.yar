rule Virus_Hijack_Gen_Trojan_ShellObject_wSZ_a024O7m_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.wSZ@a024O7m_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b50e65ba6d238906c4b6e4f52ad212e8ba253e7292ff35017e3c344acbed7023"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "5FYou must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}