rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_aGCmnff_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@aGCmnff_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0790ff69a565bd50d8f9ae5cc7b2bf668fe235a6f321f36deb52feec1e0bd5b"

  strings:
    $s1 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}