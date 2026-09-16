rule Virus_Hijack_GenPack_Backdoor_Hangup_B_284_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_284_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e94972d9721e7bd6a51ff787c61768b368e2cd8288bd8b9e6733298331a1a97f"

  strings:
    $s1 = ".IEC 61961-2.1 Default RGB colour space - sRGB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}