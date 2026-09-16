rule Virus_Hijack_Trojan_GenericKDZ_105924_362_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_362_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2140e777a6cdac40075886f87294e6217e303b6003b374702e67137601319944"

  strings:
    $s1 = "Neer?*U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}