rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4a39f739e9d385ccf18972574862f4ed5634f877d92f7a6333b592a6ab8a2b"

  strings:
    $s1 = "w=Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}