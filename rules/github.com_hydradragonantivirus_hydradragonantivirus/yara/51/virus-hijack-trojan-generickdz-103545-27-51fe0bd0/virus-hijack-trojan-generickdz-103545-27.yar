rule Virus_Hijack_Trojan_GenericKDZ_103545_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85508d250315ecad1a1660c889e8997923ad332d1249ad66ab87381617973682"

  strings:
    $s1 = "www.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time with`" fullword ascii
    $s2 = "Esoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}