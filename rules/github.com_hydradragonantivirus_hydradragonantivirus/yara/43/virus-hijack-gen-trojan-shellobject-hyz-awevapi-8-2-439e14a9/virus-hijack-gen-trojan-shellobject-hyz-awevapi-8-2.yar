rule Virus_Hijack_Gen_Trojan_ShellObject_hyZ_aWevApi_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hyZ@aWevApi_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a14eee036c9f97bc2e075326c2b23f515cea794cb486a8704172a2f7da3e474"

  strings:
    $s1 = "($rICE" fullword ascii
    $s2 = "Q)$rICe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}