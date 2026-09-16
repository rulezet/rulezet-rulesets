rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_aSzGK_f_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f505b861442ff7c6643f356020e6d2da923633f11aba5e884d5255c75d837b6"

  strings:
    $s1 = "<Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}