rule Trojan_Danger_Trojan_GenericKD_67064203_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97aa969158e409e770613ce3f43b3ff9c34554fe3a823b40b4cd3a15de6dc450"

  strings:
    $s1 = "zvjF*`pAar:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}