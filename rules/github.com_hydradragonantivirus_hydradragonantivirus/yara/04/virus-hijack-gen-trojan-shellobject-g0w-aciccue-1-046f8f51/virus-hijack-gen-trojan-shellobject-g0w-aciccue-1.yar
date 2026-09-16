rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_aCiCCue_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@aCiCCue_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c84cb190eb6b3d372370fb1b1fdce0ca00633dd7444a0236ba82ee2a33196d5"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii
    $s3 = "71giving rise to the dispute, and the relief requested. You must send any Notice of Dispute by U.S. Mail to" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}