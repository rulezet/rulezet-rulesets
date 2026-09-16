rule Virus_Delself_Application_Generic {
  meta:
    description = "datamaliciousorder - file Virus.Delself_Application.Generic.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40fb1ed8e17179cac170880bca8c410726adf0bd5ced4f9a71f256d05f2a6eb3"

  strings:
    $s1 = "?point" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}