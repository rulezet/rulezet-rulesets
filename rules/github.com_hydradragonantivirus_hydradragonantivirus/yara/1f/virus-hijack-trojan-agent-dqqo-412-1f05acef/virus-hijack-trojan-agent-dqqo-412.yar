rule Virus_Hijack_Trojan_Agent_DQQO_412 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_412.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22166d79d0bfdd76702fe2f00b03a5d9ff82517b8f72b42b7346554dff7b94f7"

  strings:
    $s1 = "S^IXfTR;SUNk" fullword ascii
    $s2 = "x*DIOl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}