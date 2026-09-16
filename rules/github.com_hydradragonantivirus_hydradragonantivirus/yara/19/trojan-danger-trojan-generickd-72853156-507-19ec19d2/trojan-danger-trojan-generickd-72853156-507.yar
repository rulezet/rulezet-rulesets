rule Trojan_Danger_Trojan_GenericKD_72853156_507 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_507.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355df06e37b40115179184e8409d75c074c799fa6043d7d592d044bf364c615a"

  strings:
    $s1 = "6uE:ADAw" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}