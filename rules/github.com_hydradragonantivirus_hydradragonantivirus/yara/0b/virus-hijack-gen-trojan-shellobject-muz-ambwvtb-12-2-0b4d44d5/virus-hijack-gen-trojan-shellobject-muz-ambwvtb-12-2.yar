rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9668cefc6ab91204aead00c56b78490106992441a6412c3c2b30f136865e62d"

  strings:
    $s1 = "LOWa:-Ea" fullword ascii
    $s2 = "LOka:-K" fullword ascii
    $s3 = "LOwa:-O" fullword ascii
    $s4 = "LOwa:-Ea" fullword ascii
    $s5 = "NOOn:-H" fullword ascii
    $s6 = "LOKe:-K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}