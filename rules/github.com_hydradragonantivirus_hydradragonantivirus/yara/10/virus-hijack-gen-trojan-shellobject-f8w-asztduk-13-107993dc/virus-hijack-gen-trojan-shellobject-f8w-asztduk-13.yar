rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4beab792062469c29bec9869e2409ddc50ef32ee42d6a95f73349425b7a470f"

  strings:
    $s1 = "kor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}