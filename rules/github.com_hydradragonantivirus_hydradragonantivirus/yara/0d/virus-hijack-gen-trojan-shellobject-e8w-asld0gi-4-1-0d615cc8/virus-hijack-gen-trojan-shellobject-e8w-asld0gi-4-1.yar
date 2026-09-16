rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad07c96da2c45b13643150a15b759e39696f5e065e763dbb8965bdbad9cc36d3"

  strings:
    $s1  = "%rnddir%\\%rand%.exe" fullword ascii
    $s2  = "%rnddir%\\%rand%.com" fullword ascii
    $s3  = " :Logare corecta - Nivel:MASTER" fullword ascii
    $s4  = "File(%tmp%\\" fullword ascii
    $s5  = "<Description type=\"string\">" fullword ascii
    $s6  = "<Description type=\"string\">XTR</Description>" fullword ascii
    $s7  = "File(%cur%\\" fullword ascii
    $s8  = "File(%win%\\" fullword ascii
    $s9  = "File(%sys%\\" fullword ascii
    $s10 = " :Failed To Add Random Garbage To (" fullword ascii
    $s11 = "%rand%" fullword ascii
    $s12 = "<Share>" fullword ascii
    $s13 = "<Directory>" fullword ascii
    $s14 = "File(\\" fullword ascii
    $s15 = "Library>G" fullword ascii
    $s16 = "QUIT :Quiting" fullword ascii
    $s17 = " :Added Random Garbage To (" fullword ascii
    $s18 = " :Adaugata copie in REGISTRY" fullword ascii
    $s19 = "BattleField 1942" fullword ascii
    $s20 = "(Director Windows: " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}