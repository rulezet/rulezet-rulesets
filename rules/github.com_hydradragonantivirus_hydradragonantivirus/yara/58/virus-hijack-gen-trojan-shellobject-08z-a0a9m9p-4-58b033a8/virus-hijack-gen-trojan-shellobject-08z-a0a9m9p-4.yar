rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "620cf41c322c7bfe51ec7d3f5ddf98ce101c0a57ad2467a7db7368cc02687420"

  strings:
    $s1 = "cLSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}