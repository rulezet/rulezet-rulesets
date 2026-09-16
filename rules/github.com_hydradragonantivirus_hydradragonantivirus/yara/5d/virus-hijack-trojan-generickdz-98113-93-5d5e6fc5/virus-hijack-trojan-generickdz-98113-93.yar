rule Virus_Hijack_Trojan_GenericKDZ_98113_93 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_93.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39bcc62a274980766d01a71a078dac70dcd9e5f4cbd4c0fd54913088973b0d57"

  strings:
    $s1 = "[}or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}