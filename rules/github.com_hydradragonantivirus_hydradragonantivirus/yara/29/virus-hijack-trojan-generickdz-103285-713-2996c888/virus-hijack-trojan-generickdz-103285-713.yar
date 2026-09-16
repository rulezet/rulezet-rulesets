rule Virus_Hijack_Trojan_GenericKDZ_103285_713 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_713.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad582f9987f0dc858ad71562a6b836eca32685590c0140ce4a990f64342a3756"

  strings:
    $s1 = "l2What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}