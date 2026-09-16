rule Virus_Danger_Gen_Trojan_ShellObject_g4Y_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.g4Y@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823043ba9b4b80954134a86808cd4f53a1e6b320196b7d1708c6072fb5b6e00f"

  strings:
    $s1 = "Nmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}