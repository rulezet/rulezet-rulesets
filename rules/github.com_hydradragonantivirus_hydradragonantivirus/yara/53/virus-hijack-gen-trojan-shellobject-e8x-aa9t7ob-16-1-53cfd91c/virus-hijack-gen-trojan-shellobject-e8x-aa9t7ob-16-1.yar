rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ba26277038082045e06c102ae5ca998339f20de977c726f06deae857b3408f"

  strings:
    $s1 = "Select * from AntiVirusProduct" fullword wide
    $s2 = "alive??" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}