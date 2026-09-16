rule Virus_Hijack_Trojan_Agent_DQQO_405 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_405.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "018a8aac6be68bfeafd4435092a6a6b01ebdb21c5b0fa329598c896d93f7101f"

  strings:
    $s1 = "!cautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}