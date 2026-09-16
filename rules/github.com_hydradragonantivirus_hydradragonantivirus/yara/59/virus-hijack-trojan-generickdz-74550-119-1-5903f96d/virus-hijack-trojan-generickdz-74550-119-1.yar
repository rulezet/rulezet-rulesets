rule Virus_Hijack_Trojan_GenericKDZ_74550_119_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "222cc7854d458416103c6a9e5519c3834db50b6a5b86de9232ebb9d47def8e82"

  strings:
    $s1 = "%\"LimE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}