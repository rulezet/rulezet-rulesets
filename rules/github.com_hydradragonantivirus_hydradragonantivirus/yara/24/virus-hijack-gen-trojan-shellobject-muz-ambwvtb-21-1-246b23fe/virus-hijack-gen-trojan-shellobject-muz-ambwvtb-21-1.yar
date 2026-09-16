rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d33f528fd7923bd467e28ab363c75742cc2df7a1a94bc4d7e1384a2b036ee4"

  strings:
    $s1 = "edit box" fullword ascii
    $s2 = "Type something here" fullword ascii
    $s3 = "LoWy<_N\\" fullword ascii
    $s4 = "Y#o?whun{" fullword ascii
    $s5 = "RegistryDemo MFC Application" fullword wide
    $s6 = "RegistryDemo Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}