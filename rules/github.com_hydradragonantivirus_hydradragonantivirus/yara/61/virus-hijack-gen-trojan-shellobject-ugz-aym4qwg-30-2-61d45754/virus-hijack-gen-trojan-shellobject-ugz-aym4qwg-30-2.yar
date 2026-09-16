rule Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_30_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_30_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90eb5a770e3032158691726670bee2968196739ab28dc06acb7afbb40082af8e"

  strings:
    $s1 = "\"Altern>" fullword ascii
    $s2 = "File*?Y" fullword ascii
    $s3 = "sc quota" fullword ascii
    $s4 = "Retry<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}