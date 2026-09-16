rule Virus_Hijack_Trojan_GenericKDZ_105924_280_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "297c5414baee415dd224b9a027012ecaa4facc44356094005094d591675950a2"

  strings:
    $s1 = "WaWa,y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}