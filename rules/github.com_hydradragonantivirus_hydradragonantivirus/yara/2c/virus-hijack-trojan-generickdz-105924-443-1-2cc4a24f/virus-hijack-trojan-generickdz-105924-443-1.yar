rule Virus_Hijack_Trojan_GenericKDZ_105924_443_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_443_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37a59e8f59656b3942b7731ba0503bd2643db7314826ada81e10a4a180ac1ab2"

  strings:
    $s1 = "GoWk<~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}