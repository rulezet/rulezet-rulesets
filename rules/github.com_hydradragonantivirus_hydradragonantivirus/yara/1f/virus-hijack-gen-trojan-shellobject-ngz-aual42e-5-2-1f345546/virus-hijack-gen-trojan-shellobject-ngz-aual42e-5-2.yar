rule Virus_Hijack_Gen_Trojan_ShellObject_nGZ_auAl42e_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.nGZ@auAl42e_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04d846c6851da528029149c2535aed5291dc6e5389438847e67e63137f75f4ff"

  strings:
    $s1 = "m@TOGs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}