rule Virus_Injector_Trojan_GenericKDZ_97791_2 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.GenericKDZ.97791_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82f2c19b34870947ceeb3c7bb20622ed8df320db338fa6bfb9c0f0ad5235c612"

  strings:
    $s1 = "D{sitH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}