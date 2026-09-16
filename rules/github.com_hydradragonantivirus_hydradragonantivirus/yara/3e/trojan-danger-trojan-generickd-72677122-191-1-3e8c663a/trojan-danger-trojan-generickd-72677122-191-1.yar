rule Trojan_Danger_Trojan_GenericKD_72677122_191_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_191_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01b97b416a8efd2a7f7a744ae355f380947badff2204cad261af94fe32f52161"

  strings:
    $s1 = "Splitting string \"%s\" into tokens:" fullword ascii
    $s2 = "- This, a sample string." fullword ascii
    $s3 = "The sentence entered is %u characters long." fullword ascii
    $s4 = "Enter a sentence: " fullword ascii
    $s5 = "How long do you want the string? " fullword ascii
    $s6 = "Random string: %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}