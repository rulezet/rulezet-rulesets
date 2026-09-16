rule Virus_Hijack_Generic_Dacic_76A3436A_A_2BEC046A {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Dacic.76A3436A.A.2BEC046A.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b90aef5b8e5ee7256b465ce0e9a5ecf03b0bd1e89893b038468c4940b04c0f"

  strings:
    $s1 = "soft Visual Studio\\d98" fullword ascii
    $s2 = "_vba,Open" fullword ascii
    $s3 = "LeHR,D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}