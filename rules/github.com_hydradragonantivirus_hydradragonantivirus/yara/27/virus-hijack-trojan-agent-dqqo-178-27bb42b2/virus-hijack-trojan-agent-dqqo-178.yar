rule Virus_Hijack_Trojan_Agent_DQQO_178 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_178.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab59efaddee679b84671b8c12b8891a224d6d3174235e252bdb0174a66c27353"

  strings:
    $s1 = "i5{')]bUNT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}