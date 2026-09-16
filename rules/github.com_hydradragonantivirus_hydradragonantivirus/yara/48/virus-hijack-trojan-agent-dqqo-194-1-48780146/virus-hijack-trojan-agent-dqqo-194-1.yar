rule Virus_Hijack_Trojan_Agent_DQQO_194_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "811bb84b42074a351b517b447725c53e34e6e0e33b5320fd8a94b779bbd03da7"

  strings:
    $s1 = ".IEC 61966-2.1 Default RGA colour space - sRGB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}