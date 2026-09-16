rule Virus_Hijack_Trojan_Agent_DQQO_225 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_225.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d75847c5821eab2d73f169f03cbaac0a771733ede221e62d77de3ec48db3d702"

  strings:
    $s1 = ")automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}