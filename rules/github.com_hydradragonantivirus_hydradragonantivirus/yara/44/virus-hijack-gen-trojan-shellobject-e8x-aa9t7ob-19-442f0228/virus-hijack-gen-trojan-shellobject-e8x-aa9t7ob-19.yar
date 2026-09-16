rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6dfbc27684068b80860de0625be6fe5587a133a1c77dcbebea0c51967e1f89c"

  strings:
    $s1 = "User(5x" fullword ascii
    $s2 = "<Module>{A97FC40B-F920-4976-906E-00803A6EE8E3}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}