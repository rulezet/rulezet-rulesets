rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fe6c977dc71ce76d1a6a81ff3296a19226e761c179fbf33d8d631e2685bb9a5"

  strings:
    $s1 = "]or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}