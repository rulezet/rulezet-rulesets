rule Trojan_Danger_Trojan_GenericKD_67166905_224_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6cfa6b4e455b1e76dd2999eb3b09475561bdcfb6d43726aed571cce770b6383"

  strings:
    $s1 = "fmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}