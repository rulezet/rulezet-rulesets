rule TRELLIX_ARC_RANSOM_Wastedlocker: RANSOMWARE FILE {
  meta:
    description    = "Rule to detect unpacked samples of WastedLocker"
    author         = "McAfee ATR Team"
    id             = "900923cf-75c0-5342-858d-fe1ffa9486bd"
    date           = "2020-07-27"
    modified       = "2020-10-12"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_wastedlocker.yar#L1-L32"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "c5adf88a46c34c8683d0e3d70529b352c77209f004e6c638ff079ea025921781"
    score          = 75
    quality        = 70
    tags           = "RANSOMWARE, FILE"
    rule_version   = "v1"
    malware_type   = "ransomware"
    malware_family = "Ransom:W32/WastedLocker"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"
    hash1          = "ae255679f487e2e9075ffd5e8c7836dd425229c1e3bd40cfc46fbbceceec7cf4"

  strings:
    $pattern_0 = { 8d 45 fc 50 53 53 6a 19 ff 75 f8 }
    $pattern_1 = { 66 83 3b 00 8b f3 0f 84 85 00 00 00 8b 7d 10 8b 47 2c 85 c0 74 10 }
    $pattern_2 = { e8 ?? ?? ?? ?? 8b 4d 08 8b 45 18 8d 04 41 66 83 60 02 00 83 c4 0c 83 7d 14 00 }
    $pattern_3 = { 87 01 e9 ?? ?? ?? ?? 8b c7 5f 5e 5b }
    $pattern_4 = { 8b f8 3b fb 74 2f 53 8d 45 fc 50 56 }
    $pattern_5 = { 6a 10 8d 45 f0 6a 00 50 e8 ?? ?? ?? ?? 83 c4 0c 5e }
    $pattern_6 = { 5f 5d c2 08 00 55 8b ec }
    $pattern_7 = { 8d 7e 04 ff 15 ?? ?? ?? ?? 85 c0 89 45 e8 74 0e 2b 45 10 }
    $pattern_8 = { ff 15 ?? ?? ?? ?? 8b 45 dc 8b 4d bc 69 c0 0d 66 19 00 05 5f f3 6e 3c 89 45 dc }
    $pattern_9 = { 8b 4d 08 8b 19 03 d8 f7 d0 c1 c6 0f 03 f2 0b c6 }

  condition:
    7 of them and filesize < 1806288
}