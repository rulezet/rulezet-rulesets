rule Trojan_Autorun_Trojan_GenericKDZ_94847_69_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a92e0bbe17f17206a40fc32b8e699519d39cfe5586b72b3d85992ec622e04a7"

  strings:
    $s1 = "`automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}