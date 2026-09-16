rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aCV_JGo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aCV@JGo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc85a3b0adcb02cf50469381af6d0ba9ece084774a905e001aa93b2052857fcb"

  strings:
    $s1 = "#Powered by SmartAssembly 6.12.5.799" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}