rule Virus_Hijack_Trojan_GenericKDZ_105924_102_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09378fa6422837542139d3669649d574c4c7a876f48416291a258f7cfa9af0e1"

  strings:
    $s1 = "4`HizZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}