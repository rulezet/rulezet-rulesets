rule Virus_Hijack_Trojan_GenericKDZ_105924_314_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_314_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c843b0835a3a1b8efe5f1436aa4b47b998653a63e7b1b5f1ba85dd9f7ebbcc8b"

  strings:
    $s1 = "%6%maHa" fullword ascii
    $s2 = "B<URal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}