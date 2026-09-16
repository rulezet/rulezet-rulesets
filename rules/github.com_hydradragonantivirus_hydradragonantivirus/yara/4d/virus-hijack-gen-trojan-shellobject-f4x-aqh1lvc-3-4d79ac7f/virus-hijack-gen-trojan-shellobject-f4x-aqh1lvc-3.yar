rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1e3c4fbb1eea4e18455edf9d0771154bb756dede342fcdad4b01e8a4d3b2f98"

  strings:
    $s1 = "?-must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}