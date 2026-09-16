rule Virus_Hijack_Trojan_GenericKDZ_74550_369_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_369_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78d24fb0a0f496aa15963fd8165f35218134eef9ad78546a501457e91d79c0b8"

  strings:
    $s1 = "bRig;Td" fullword ascii
    $s2 = "beam$]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}