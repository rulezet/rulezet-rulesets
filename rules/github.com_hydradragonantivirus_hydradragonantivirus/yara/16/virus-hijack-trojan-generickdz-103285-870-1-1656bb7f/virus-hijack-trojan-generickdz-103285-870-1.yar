rule Virus_Hijack_Trojan_GenericKDZ_103285_870_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_870_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7c6f1ce0ca401e8a9558e19eb928f2f8291dca30cf74ac5a9f225c158c5ffa6"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}