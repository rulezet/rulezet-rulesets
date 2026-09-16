rule Virus_Hijack_Gen_Trojan_ShellObject_g4Y_aqH1LVc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4Y@aqH1LVc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b240048f5d569b92e8f3ea74a314275384e0d8897d91e36d146c14e9f879c939"

  strings:
    $s1 = "!Jmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}