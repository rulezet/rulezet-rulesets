rule Virus_Hooker_Trojan_GenericKD_48560802_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d26e54521830f4de29876ed5789cc8536004b649344bb7c234b548c8310582e1"

  strings:
    $s1 = "ZfYqL\"aUCa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}