rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b1a45173ab7610ee57bae08ea3462321976a5608fb0ace6d0bc6833f6373bd"

  strings:
    $s1 = "xautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}