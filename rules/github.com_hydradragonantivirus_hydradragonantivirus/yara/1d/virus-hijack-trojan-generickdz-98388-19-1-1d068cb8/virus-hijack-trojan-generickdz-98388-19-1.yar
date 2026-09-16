rule Virus_Hijack_Trojan_GenericKDZ_98388_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae9d90454ee46006a8c969c192f084799cce9da8c6b8fb86cd5acee169990626"

  strings:
    $s1 = "UnzE,z" fullword ascii
    $s2 = "a1(fRET" fullword ascii
    $s3 = "nOIr)l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}