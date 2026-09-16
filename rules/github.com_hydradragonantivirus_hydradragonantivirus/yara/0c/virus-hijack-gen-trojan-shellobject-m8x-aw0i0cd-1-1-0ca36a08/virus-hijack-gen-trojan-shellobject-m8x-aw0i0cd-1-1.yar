rule Virus_Hijack_Gen_Trojan_ShellObject_m8X_aW0I0Cd_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8X@aW0I0Cd_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "582b7980995dafb80eb9943c9e7e2b9765a67a163ff8ed8cfdedd2e31c5d3cd0"

  strings:
    $s1 = "Copyright 2017 Google Inc. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}