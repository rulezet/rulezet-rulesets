rule Virus_Hijack_GenPack_Backdoor_Hangup_B_462_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_462_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0e1b578aa1f87982c39ffa83a2ac1dfde5be899954d5fd878dc7c5858bc5bb2"

  strings:
    $s1 = "Licensing Component" fullword wide
    $s2 = ",Rich@}" fullword ascii
    $s3 = "TYee:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}