rule Virus_Hijack_Trojan_GenericKDZ_103285_774 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_774.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "116827dde6cf0237c2bf6943439e1c1396008f92141b658df613e92e1c18281f"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}