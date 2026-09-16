rule Trojan_Danger_Trojan_GenericKD_67166905_321_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_321_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426369428643321448a332db8114e9acb4c393b0d6258a581b71eaeba82036d9"

  strings:
    $s1 = ")shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}