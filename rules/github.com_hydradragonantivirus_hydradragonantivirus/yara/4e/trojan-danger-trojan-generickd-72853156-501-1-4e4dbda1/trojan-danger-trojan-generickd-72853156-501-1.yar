rule Trojan_Danger_Trojan_GenericKD_72853156_501_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_501_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69a3cd21facb7a3607f1f3250593c205ba40654557c1bdad1c5b46945238a78"

  strings:
    $s1 = "n?Crea" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}