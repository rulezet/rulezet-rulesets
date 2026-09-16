rule Trojan_Autorun_Trojan_GenericKDZ_94847_422_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_422_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e125463b02494dbcf5597e68ffc2e140f5d71d6ff7fc2cbd55c86e08a2784ca3"

  strings:
    $s1 = "3lyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii
    $s2 = "and you and Oracle agree to submit to the exc`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}