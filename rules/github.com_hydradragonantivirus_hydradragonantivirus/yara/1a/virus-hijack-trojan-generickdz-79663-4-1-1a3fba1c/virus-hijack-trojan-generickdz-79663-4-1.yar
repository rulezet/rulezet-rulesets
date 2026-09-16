rule Virus_Hijack_Trojan_GenericKDZ_79663_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2791bd4d29370652da9da1b04cc615849aa820e3200ba9d01ff1f0dadc6c04b9"

  strings:
    $s1 = "Hy,/*bosH" fullword ascii
    $s2 = "DuRe{d" fullword ascii
    $s3 = "H}lynx" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}