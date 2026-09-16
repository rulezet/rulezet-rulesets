rule Trojan_Danger_Trojan_GenericKD_67166905_147_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65aac3476441f6dcafa500d34af23cd210e1c2ca7236efa1851d6b328feb0174"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}