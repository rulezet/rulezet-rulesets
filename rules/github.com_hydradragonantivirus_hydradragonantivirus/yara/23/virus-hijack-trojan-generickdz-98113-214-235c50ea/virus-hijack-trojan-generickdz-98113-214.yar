rule Virus_Hijack_Trojan_GenericKDZ_98113_214 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_214.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acee5cdb8467caac0a0236f56a47bee8e09b18716a4070529d47254fff349c19"

  strings:
    $s1 = "8@4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "8!SiDI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}