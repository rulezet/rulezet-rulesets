rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bdf65042fd507d4db8327dacfff33d46d4a36500cecbf99254036230ef7e0b0"

  strings:
    $s1 = "DOut)5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}