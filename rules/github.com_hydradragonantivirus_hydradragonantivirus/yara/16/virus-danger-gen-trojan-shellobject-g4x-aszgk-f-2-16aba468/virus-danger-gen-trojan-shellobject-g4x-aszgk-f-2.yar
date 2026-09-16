rule Virus_Danger_Gen_Trojan_ShellObject_g4X_aSzGK_f_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g4X@aSzGK!f_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bda5803cdb5abbb7bdbc1ae53342b66e1c238701bc9de6ce6206e0724a7b2b5b"

  strings:
    $s1 = "\\QOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}