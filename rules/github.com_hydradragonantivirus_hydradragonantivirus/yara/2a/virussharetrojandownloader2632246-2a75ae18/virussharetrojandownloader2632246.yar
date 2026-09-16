rule VirusShareTrojanDownLoader2632246 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader2632246.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69cd57994729a44cf6f5511078b3e284a77974ef0f14a423b746dab45310b175"

  strings:
    $s1 = "Crypted" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}