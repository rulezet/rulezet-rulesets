rule VirusShareBackDoorSpyBotNET35 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorSpyBotNET35.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c45d8458a5d2d7155ce7e55f38d607ae9d18808fb55707f992bd38d635bf571"

  strings:
    $s1 = "Buy & sell Crypto in minutes, join the world" fullword wide
    $s2 = "s largest crypto exchange." fullword wide
    $s3 = "w4%BraY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}