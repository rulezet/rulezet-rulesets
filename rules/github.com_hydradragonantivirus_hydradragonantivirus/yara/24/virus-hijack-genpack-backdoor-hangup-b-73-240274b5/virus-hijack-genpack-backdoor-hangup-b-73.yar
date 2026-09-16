rule Virus_Hijack_GenPack_Backdoor_Hangup_B_73 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_73.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd8b74b3ca96a1ea7906260c2c5501e699105b4dd780f6bafc7730dc937bd34"

  strings:
    $s1 = "eyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}