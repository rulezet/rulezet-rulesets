rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "707c8e1552f911b20804a562692d38484899a2163c5e437482083e731ef0cbcb"

  strings:
    $s1 = "Mhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}