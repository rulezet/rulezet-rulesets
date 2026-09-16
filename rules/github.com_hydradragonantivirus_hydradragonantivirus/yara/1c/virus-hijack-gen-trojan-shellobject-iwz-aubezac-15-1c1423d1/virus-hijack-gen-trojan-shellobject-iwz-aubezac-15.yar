rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9837031baf3fa53de6025f3f91092203b9ceb08a180e80eb7aa75e785ca9c677"

  strings:
    $s1 = "u~automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}