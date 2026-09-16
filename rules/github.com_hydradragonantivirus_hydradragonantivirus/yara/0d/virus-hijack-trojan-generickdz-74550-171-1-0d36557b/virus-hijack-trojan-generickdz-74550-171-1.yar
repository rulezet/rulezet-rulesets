rule Virus_Hijack_Trojan_GenericKDZ_74550_171_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_171_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "217549922224ec6e36994c15259ecbafd074f21e04885c489ca8cc4a3ed136a4"

  strings:
    $s1 = "INlY%:s}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}