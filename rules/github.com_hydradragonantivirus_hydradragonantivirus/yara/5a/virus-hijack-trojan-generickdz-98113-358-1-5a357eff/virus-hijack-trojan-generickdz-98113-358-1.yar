rule Virus_Hijack_Trojan_GenericKDZ_98113_358_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_358_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edb1fbbab1f4d7e9d296b4ef33913f217955d72d9f9f75e47cd6e76a399e95b4"

  strings:
    $s1 = "@nAkO(;%bd" fullword ascii
    $s2 = "v?garB" fullword ascii
    $s3 = "tAhR,p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}