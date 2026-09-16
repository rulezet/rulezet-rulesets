rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aCZnhbe_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aCZnhbe_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0346b19407f6fb93ac15ad0d5bea82b97df44e7fc7935d7813666f4333cbc77e"

  strings:
    $s1 = "|available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii
    $s2 = "aWFU<o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}