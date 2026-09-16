rule Virus_Hijack_Trojan_GenericKDZ_103285_86_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7df8cc868719237e6a10183e66c3fb0ced11ef2ac8a77e696286390b04f5c8a"

  strings:
    $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c142 79.160924, 2017/07/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}