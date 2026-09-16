rule Virus_Hijack_Trojan_GenericKDZ_98113_264_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_264_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9607cfd5312baa12fc5922b82eecc849f27ba02aa46dc0499a2391ead0e79a"

  strings:
    $s1 = ">coBBy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}