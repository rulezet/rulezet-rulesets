rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2db04b76aa2c5ca3f551e62c12672ce7f9f69f16ab09ba2272b5e719c4d947d"

  strings:
    $s1 = "T_by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}