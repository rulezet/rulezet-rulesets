rule Virus_Hijack_Trojan_Agent_DQQO_316 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_316.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27a1aa16e79bd58f4c9e542f0184343745aa23bdcbafe9607ea767023c0b874"

  strings:
    $s1 = "\\?S8Q0delivery. Oracle also warrants that services ordered will be provided in a professional manner consistent with industry" fullword ascii
    $s2 = "Named User P" fullword ascii
    $s3 = "browser window. THE ADDITIONA L TERMS CONTA IN A BINDING ARBITRA TION CLA USE A NDu/E" fullword ascii
    $s4 = "JYou must be a " fullword ascii
    $s5 = "O. Other(" fullword ascii
    $s6 = "5`DoraD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}