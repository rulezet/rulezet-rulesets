rule Virus_Hijack_Gen_Trojan_ShellObject_q4Z_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q4Z@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fa2b350386292fcfc0d2fa71c62d9d610acdc17f7e4b14285ced84fe9431220"

  strings:
    $s1 = "Wmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}