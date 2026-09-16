rule Virus_Hijack_Trojan_GenericKDZ_103285_394 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_394.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "313fdfddd68e15e133ce262adb86172b8b087dc87e82c3be0cdd7820f3d27367"

  strings:
    $s1 = "Kpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}