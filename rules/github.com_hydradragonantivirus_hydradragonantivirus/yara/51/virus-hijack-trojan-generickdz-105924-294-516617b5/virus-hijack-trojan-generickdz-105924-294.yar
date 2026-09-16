rule Virus_Hijack_Trojan_GenericKDZ_105924_294 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_294.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "620d651ee5f5cd0d15acc44f1462457049a5afe7be4f74b8098dca7c34d9969d"

  strings:
    $s1 = "&9mYe(:-5%aLms" fullword ascii
    $s2 = "&%aLms" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}