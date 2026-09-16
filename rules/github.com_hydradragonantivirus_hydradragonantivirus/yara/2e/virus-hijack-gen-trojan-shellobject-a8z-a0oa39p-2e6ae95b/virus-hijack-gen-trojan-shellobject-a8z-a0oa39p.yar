rule Virus_Hijack_Gen_Trojan_ShellObject_A8Z_a0oa39p {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.A8Z@a0oa39p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a8bf258f52ced421cf3452f6adbce07b1547684e970b60006215862c60ef7d6"

  strings:
    $s1 = "availability of Extended Support and Extended Maintenance Supp" fullword ascii
    $s2 = "$M in Managed Assets: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four hundredP" fullword ascii
    $s3 = "lZPerson: is defined as your employee or contractor who is actively working on behalf of your organization or a former" fullword ascii
    $s4 = "may renew your order for an additiona`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}