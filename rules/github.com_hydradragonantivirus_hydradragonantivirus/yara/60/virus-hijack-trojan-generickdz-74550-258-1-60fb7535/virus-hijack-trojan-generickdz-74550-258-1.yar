rule Virus_Hijack_Trojan_GenericKDZ_74550_258_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_258_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "921479a112f34b143bfc578b1d5cd322015ccdb338f7404895ad8a9ab456be24"

  strings:
    $s1 = "GEuM(v" fullword ascii
    $s2 = ">dESi[(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}