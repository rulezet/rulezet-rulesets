rule Trojan_Danger_Trojan_GenericKD_67166905_293_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_293_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a65a07a007088ae69bce0122bc77cc7f8547f149f07a5dd45fec24d9156661dd"

  strings:
    $s1 = "~4must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}