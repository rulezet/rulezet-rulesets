rule Virus_Hijack_Trojan_GenericKDZ_98388_136_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc156cb112ea5e38b2df55836fbf8f6b87d876e392b489da578b4663b14dbd25"

  strings:
    $s1 = "Ao,uVIC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}