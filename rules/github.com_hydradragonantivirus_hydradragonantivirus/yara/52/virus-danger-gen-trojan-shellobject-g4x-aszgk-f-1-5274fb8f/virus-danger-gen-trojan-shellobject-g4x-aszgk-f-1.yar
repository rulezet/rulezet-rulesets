rule Virus_Danger_Gen_Trojan_ShellObject_g4X_aSzGK_f_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g4X@aSzGK!f_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72bf6b15b1a2ca069c3072bcf9a026cd8b9096ab5831b23ee6a26bff9ec23ab1"

  strings:
    $s1 = "?0Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}