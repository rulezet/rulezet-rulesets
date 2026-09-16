rule Virus_Hijack_Trojan_GenericKDZ_74550_275_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8034a06fdb478e16fadf5b02a21b66b92469af2cea704631226be7bd37c6aa13"

  strings:
    $s1 = "baLd'%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}