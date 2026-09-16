rule Virus_Danger_Gen_Trojan_ShellObject_uCZ_amHJK4p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.uCZ@amHJK4p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229b192cd496e2a68f9e4dcc0ed3a6a76d9997cd34ff6603a53a5c476f9a0562"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii
    $s2 = "TRap?<RRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}