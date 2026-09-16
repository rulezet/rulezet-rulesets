rule Virus_Hijack_Trojan_Agent_DQQO_304 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_304.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "241d8f4146ea08077a1b1dc3b125a1f23db27b46bb58971ab81842c623c593d1"

  strings:
    $s1 = "8Orders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}