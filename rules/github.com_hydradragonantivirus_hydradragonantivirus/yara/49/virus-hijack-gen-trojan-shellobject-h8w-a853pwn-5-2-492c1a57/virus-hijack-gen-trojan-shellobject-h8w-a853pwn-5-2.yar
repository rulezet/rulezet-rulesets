rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91ab732685d17ae6473b16ffca0a15e38976982b2b91b562712aa0f3419432e7"

  strings:
    $s1 = "Content-Disposition: attachment; filename=PurpleMood.scr" fullword ascii
    $s2 = "RCPT TO: <test@pact518.hit.edu.cn>" fullword ascii
    $s3 = "Subject:hi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}