rule Virus_Hijack_Trojan_GenericKDZ_105924_504_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_504_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb7a4da7f3322de5e4e42a1fd8954c4c587ec374c3b59bba0a660ad6e2df1cae"

  strings:
    $s1 = "z`sCAn" fullword ascii
    $s2 = "%FeOd@W" fullword ascii
    $s3 = "heEl'Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}