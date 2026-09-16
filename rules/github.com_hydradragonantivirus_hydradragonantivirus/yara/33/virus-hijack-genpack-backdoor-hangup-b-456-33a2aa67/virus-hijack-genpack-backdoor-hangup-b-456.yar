rule Virus_Hijack_GenPack_Backdoor_Hangup_B_456 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_456.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "671994aeb82f0df910eb3b37a53af99efb77728e94093df89b5623a52bcc8b33"

  strings:
    $s1 = ":your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}