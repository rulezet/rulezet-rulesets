rule Virus_Hijack_Trojan_GenericKDZ_105924_59_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_59_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7482af7a1522eb017bc32b6b1f78cb888cfcddcf17c442b0a52958e92f6f6d51"

  strings:
    $s1 = "(Quot#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}