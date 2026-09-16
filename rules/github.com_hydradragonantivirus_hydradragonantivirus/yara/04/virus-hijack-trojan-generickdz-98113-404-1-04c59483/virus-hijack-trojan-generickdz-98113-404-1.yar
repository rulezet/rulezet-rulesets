rule Virus_Hijack_Trojan_GenericKDZ_98113_404_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_404_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efaca5db3dc73a655657a480bce5d291529dab37aecd795338a31e0a8dac1576"

  strings:
    $s1 = "DUbb,?N" fullword ascii
    $s2 = "_ux[PitH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}