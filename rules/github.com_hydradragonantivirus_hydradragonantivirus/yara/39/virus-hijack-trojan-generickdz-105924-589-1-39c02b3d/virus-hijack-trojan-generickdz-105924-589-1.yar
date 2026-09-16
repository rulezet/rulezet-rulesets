rule Virus_Hijack_Trojan_GenericKDZ_105924_589_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_589_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83e1088d1606712290a3047c51038a9e562590b770c044ad00c18ef51994d0e2"

  strings:
    $s1 = "Fair?#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}