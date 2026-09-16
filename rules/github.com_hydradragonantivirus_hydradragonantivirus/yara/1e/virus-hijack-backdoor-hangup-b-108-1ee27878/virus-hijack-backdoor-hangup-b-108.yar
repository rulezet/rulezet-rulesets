rule Virus_Hijack_Backdoor_Hangup_B_108 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_108.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5f7fd3deaf597282265ef8365a00b79aea6a19f1ddec8a877d26bab7a513825"

  strings:
    $s1 = "Gcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}