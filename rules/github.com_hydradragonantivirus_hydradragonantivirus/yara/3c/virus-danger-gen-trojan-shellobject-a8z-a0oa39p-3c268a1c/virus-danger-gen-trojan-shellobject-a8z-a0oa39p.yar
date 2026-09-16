rule Virus_Danger_Gen_Trojan_ShellObject_A8Z_a0oa39p {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.A8Z@a0oa39p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c67d28b2c9983896ece14990833f62488b137c5c79b52a78240289b0d0ae3a9f"

  strings:
    $s1 = "availability of Extended Support and Extended Maintenance Supp" fullword ascii
    $s2 = "may renew your order for an additiona" fullword ascii
    $s3 = "$M in Managed Assets: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four hundredP" fullword ascii
    $s4 = ",Person: is defined as your employee or contractor who is actively working on behalf of your organization or a former" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}