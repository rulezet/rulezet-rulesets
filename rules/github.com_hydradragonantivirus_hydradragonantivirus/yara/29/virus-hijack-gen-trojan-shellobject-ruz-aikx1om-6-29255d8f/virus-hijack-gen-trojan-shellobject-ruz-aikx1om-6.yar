rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640d88540e19ecd4b0fb10dc9e8c6ef8c084631012634020848e11715036a704"

  strings:
    $s1 = "netsh.exe interface ip set address " fullword wide
    $s2 = "netsh.exe interface ip set dns name=" fullword wide
    $s3 = "netsh.exe interface ip add dns name=" fullword wide
    $s4 = "\"CHENGDU AOMEI TECHNOLOGY CO., LTD.1+0)" fullword ascii
    $s5 = "\"CHENGDU AOMEI TECHNOLOGY CO., LTD.0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}