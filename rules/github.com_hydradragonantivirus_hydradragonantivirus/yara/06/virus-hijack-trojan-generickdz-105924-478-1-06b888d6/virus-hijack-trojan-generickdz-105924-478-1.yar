rule Virus_Hijack_Trojan_GenericKDZ_105924_478_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_478_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fab1ea9236129cc2e135e8ec03156a1504f18044c6410fa918962d5221bc553"

  strings:
    $s1 = "!iZAR'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}