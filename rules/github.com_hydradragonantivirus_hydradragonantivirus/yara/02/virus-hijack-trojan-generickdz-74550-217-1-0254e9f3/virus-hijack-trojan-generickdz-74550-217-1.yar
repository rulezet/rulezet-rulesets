rule Virus_Hijack_Trojan_GenericKDZ_74550_217_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4668e964192e1719c7f42be4c8cc16a4c864117f20c94bf2498da4a93b69b7ed"

  strings:
    $s1 = "}LIng(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}