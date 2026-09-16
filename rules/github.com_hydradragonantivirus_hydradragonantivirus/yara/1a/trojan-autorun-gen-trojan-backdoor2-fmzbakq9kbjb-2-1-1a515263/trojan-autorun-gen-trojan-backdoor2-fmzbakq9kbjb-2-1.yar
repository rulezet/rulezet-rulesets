rule Trojan_Autorun_Gen_Trojan_Backdoor2_fmZbaKq9kbjb_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.fmZbaKq9kbjb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f1198bf170f923ff0e148531e0a6bb13becadfdeb3034b1e842cdf3b77d5d49"

  strings:
    $s1 = "bOof!NJ" fullword ascii
    $s2 = "?HINt@" fullword ascii
    $s3 = "a(2hINt`60Z$z|ZdzlZdzlZdzlZdzlZdzlZdzlZdzl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}