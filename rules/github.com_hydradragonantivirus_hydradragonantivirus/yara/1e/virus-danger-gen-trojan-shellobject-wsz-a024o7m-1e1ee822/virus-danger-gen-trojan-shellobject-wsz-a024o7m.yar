rule Virus_Danger_Gen_Trojan_ShellObject_wSZ_a024O7m {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.wSZ@a024O7m.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18eae147af321f4a372eb72b91fa0d6cf537e5259a8a62384100adeaed9d6a8d"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "0You must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}