rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f10998fb6d01e92dbec8105be7b6788e4ccecdc87f7570f60856c95564996390"

  strings:
    $s1 = "need lookahead" fullword wide
    $s2 = "Not flushing, but no lookahead" fullword wide
    $s3 = "#Error: " fullword wide
    $s4 = "future match" fullword wide
    $s5 = "Inconsistent bl_counts!" fullword wide
    $s6 = "Code lengths don't add up properly." fullword wide
    $s7 = "Created with" fullword wide
    $s8 = "application data cannot be found" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}