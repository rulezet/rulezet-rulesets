import "pe"
rule _Virus_Sysbot_Generic_Sdbot_7021C09F_Virus_Sysbot_Generic_Sdbot__205 {
  meta:
    description = "datamaliciousorder - from files Virus.Sysbot_Generic.Sdbot.7021C09F.vir, Virus.Sysbot_Generic.Sdbot.7021C09F_1.vir, Virus.Sysbot_Generic.Sdbot.7021C09F_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ae86e46da00b1dc940b7fca76228c5fd6247c26ec84dd072e9225dd65fddccc"
    hash2       = "c9aa2692d1b97670fcfca18626de4fed47c3e2930b1af1858dee460cca100477"
    hash3       = "531e5cfaae4f0eaa87340d19ca4866783a3e74d4f29c59e8fe707423ca684f54"

  strings:
    $s1 = "n IRC OperatorSuspic" fullword ascii
    $s2 = "bHOST" fullword ascii
    $s3 = "){(null" fullword ascii
    $s4 = "L FROM" fullword ascii
    $s5 = "lbg?[BACK]" fullword ascii
    $s6 = "SHiELD" fullword ascii
    $s7 = "Ke?Query" fullword ascii
    $s8 = "ket from;" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d6ea3038437d6995b6b90b472264a866" and (all of them)
    ) or (all of them)
}