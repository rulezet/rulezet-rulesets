rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "606938c343ff1eb7278561785855589f46b06dfbc6925b1bb2173d3722c9f393"

  strings:
    $s1 = "#Powered by SmartAssembly 6.11.1.433" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}