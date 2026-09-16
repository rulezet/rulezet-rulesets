rule Virus_Hijack_Trojan_GenericKDZ_103285_383 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_383.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858c4a52e3a6bdf6afe26f51e305ca7ba6b72e17bfb5f10198f1a9c178812f9c"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii
    $s2 = "%lmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}