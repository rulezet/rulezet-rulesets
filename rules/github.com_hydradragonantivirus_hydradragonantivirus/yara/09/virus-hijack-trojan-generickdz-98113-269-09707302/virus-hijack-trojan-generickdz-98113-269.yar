rule Virus_Hijack_Trojan_GenericKDZ_98113_269 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_269.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "604b804ca04d4df96fed9c4ee0e6352c91f1198cf671c3a21ae6a1076d5577ad"

  strings:
    $s1 = "^Kfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}