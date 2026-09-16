rule Trojan_Autorun_Trojan_Ransom_Doboc_A_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Ransom.Doboc.A_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db74ab5e6177b08b45130f4da4445861267c8ce10454f63402ac00b7fb93a23"

  strings:
    $s1 = "_orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}