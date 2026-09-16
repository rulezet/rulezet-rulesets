rule Virus_Hijack_Trojan_GenericKDZ_103285_129 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_129.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43969e689938a31c15e8892326157ccec475742b10e91b210177118df9c32655"

  strings:
    $s1 = "{Kremainder of Section B remaining in full force and effect." fullword ascii
    $s2 = "}Stof*$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}