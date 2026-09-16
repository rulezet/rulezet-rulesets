rule Virus_Hijack_Trojan_Peed_Gen_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8c964c91373018ff0449891bb3a1cc874f98aa95543cd1b6eebe0c01ab6d3d3"

  strings:
    $s1 = "#4$yolK" fullword ascii
    $s2 = "9&coIl" fullword ascii
    $s3 = "loch{n" fullword ascii
    $s4 = "3:EOan " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}