rule Virus_Hijack_Trojan_Agent_DQQO_175 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_175.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0844683aa5c09081365e1f9338a17912b43bf6ebbe32284a90d8a0ac81a67777"

  strings:
    $s1 = "_Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}