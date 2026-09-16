rule Virus_Hijack_Trojan_GenericKDZ_79663_95_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_95_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b56ca7fc8a64f84653859c78c18a7de9c8f0138c4e376c40b55dda8f294edf6"

  strings:
    $s1 = "% ping" fullword ascii
    $s2 = "MAwp*t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}