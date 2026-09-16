rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_14 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bd877aec8031a572f74254671b895a86eb17176ea91bb9bf9588daffe16809b"

  strings:
    $s1 = "j|k|J}?,Dikc^}koDa?eEz\"bL/(cFb\"xFj%x" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}