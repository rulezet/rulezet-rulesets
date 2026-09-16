rule Virus_Hijack_Trojan_GenericKDZ_105924_372_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_372_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e465e7f3f12516de68a2f83542cf0166da8c4a33264b4914a4b95791400a14b"

  strings:
    $s1 = "`woTe'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}