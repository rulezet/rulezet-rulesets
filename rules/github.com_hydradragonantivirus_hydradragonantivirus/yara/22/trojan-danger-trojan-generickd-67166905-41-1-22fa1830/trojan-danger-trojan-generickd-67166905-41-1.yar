rule Trojan_Danger_Trojan_GenericKD_67166905_41_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31ef1aeb5c38a5881d0c0642b8e890b99e49b6ff83f86baad7956c0f7a3f719c"

  strings:
    $s1 = "hUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}