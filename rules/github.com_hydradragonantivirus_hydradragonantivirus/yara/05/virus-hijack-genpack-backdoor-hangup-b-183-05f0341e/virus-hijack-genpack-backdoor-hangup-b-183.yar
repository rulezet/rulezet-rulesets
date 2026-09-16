rule Virus_Hijack_GenPack_Backdoor_Hangup_B_183 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_183.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9bb8b8ab2c0d891ee11fe47cb0c722b21ed088a95fa1e33e0a8746ff3794ce7"

  strings:
    $s1 = "0your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}