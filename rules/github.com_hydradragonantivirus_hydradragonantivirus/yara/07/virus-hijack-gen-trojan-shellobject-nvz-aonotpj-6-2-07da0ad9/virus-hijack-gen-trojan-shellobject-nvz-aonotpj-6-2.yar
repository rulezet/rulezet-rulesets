rule Virus_Hijack_Gen_Trojan_ShellObject_NvZ_aOnotPj_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6728bd0f40c7a0adaf897bb3f875fbedd59882dfd713020ef8b583c962f2744d"

  strings:
    $s1 = "High) " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}