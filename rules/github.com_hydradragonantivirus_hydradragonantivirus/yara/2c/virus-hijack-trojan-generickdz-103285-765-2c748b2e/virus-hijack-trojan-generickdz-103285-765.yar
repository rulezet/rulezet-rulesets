rule Virus_Hijack_Trojan_GenericKDZ_103285_765 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_765.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "166ccb5c611828658a8f4310466b96a638e8a442375a2e0baca139037557462a"

  strings:
    $s1 = "\\HThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws princip" ascii
    $s2 = "\\HThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws princip" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}