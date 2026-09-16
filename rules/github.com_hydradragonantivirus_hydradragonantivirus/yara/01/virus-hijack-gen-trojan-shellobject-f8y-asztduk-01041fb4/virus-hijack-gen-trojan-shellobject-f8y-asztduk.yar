rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "461b5bb27fb72d7a037e6b0df835db586f46fc39ad6226fccda7f1ccbca47dc5"

  strings:
    $s1 = "6or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}