rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9538506e8f4a379bd8c77e62335b31f896add70b126c3e6388278754df825b92"

  strings:
    $s1 = "S8Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}