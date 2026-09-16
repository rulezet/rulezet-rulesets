rule Virus_Hijack_GenPack_Trojan_GenericKDZ_103285_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Trojan.GenericKDZ.103285_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e10c23c0a265f962e23b8e234532f04ecf143318b3ca849d7dd442a03856f722"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}