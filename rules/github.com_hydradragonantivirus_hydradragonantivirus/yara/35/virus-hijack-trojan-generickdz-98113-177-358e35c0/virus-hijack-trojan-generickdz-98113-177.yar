rule Virus_Hijack_Trojan_GenericKDZ_98113_177 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_177.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad1a851b9f4f6519a075d303408c740f1756f3030e3529b6c44d0bbd9cfdecc"

  strings:
    $s1 = "qhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}