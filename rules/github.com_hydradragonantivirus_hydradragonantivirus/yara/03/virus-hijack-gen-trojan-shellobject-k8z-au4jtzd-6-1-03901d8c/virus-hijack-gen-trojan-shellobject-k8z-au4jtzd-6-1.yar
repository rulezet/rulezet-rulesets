rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "606adb77757326264f522f52f2289b58ac12832eb9875543c29e9ad75ce844ce"

  strings:
    $s1 = "; name" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}