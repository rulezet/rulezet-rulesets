rule Virus_Hijack_Trojan_GenericKDZ_98113_352_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_352_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddaf4e826f98a6a2c64cea04a4c0a165d891b3ae68a20227c01d458b610e64f9"

  strings:
    $s1 = "XfP EsPy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}