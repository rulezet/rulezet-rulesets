rule Virus_Hijack_Trojan_GenericKDZ_98113_223_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_223_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9794b0a3f405824dbebf9fa8f68cd9bc2c6fff3d709a77302cb9ed6d36dc68b"

  strings:
    $s1 = "joSh:;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}