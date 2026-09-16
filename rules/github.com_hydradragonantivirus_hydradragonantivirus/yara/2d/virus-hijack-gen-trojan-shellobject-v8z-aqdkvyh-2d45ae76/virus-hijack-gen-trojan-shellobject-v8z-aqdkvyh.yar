rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_aqDKVYh {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@aqDKVYh.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e97a88335532646d244e3247d438fb84156f5d358e04246eeef02b53aa8b24e"

  strings:
    $s1 = "USER'#" fullword ascii
    $s2 = "JOorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}