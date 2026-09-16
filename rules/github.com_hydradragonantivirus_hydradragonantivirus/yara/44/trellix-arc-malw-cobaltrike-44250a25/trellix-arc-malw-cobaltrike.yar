rule TRELLIX_ARC_MALW_Cobaltrike: BACKDOOR FILE {
  meta:
    description    = "Rule to detect CobaltStrike beacon"
    author         = "Felix Bilstein - yara-signator at cocacoding dot com"
    id             = "a7dae4c7-672e-58fb-8542-90fa90d991a4"
    date           = "2020-07-19"
    modified       = "2021-08-30"
    reference      = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/malware/MALW_cobaltstrike.yar#L1-L38"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "fc91d40c6544c7ab7c60b3cb8fc542bd4a6fac79dbe00cad8f612854f2a6dcd1"
    score          = 75
    quality        = 70
    tags           = "BACKDOOR, FILE"
    rule_version   = "v1"
    malware_type   = "backdoor"
    malware_family = "Backdoor:W32/CobaltStrike"
    actor_type     = "Cybercrime"
    actor_group    = "Unknown"
    hash1          = "f47a627880bfa4a117fec8be74ab206690e5eb0e9050331292e032cd22883f5b"

  strings:
    $pattern_0  = { e9 ?? ?? ?? ?? eb 0a b8 01 00 00 00 e9 ?? ?? ?? ?? }
    $pattern_1  = { 3b c7 75 0d ff 15 ?? ?? ?? ?? 3d 33 27 00 00 }
    $pattern_2  = { 8b d0 e8 ?? ?? ?? ?? 85 c0 7e 0e }
    $pattern_3  = { 50 8d 8d 24 ef ff ff 51 e8 ?? ?? ?? ?? }
    $pattern_4  = { 03 b5 d4 ee ff ff 89 b5 c8 ee ff ff 3b f7 72 bd 3b f7 }
    $pattern_5  = { 8b 45 0c 89 45 f4 8d 45 f4 50 }
    $pattern_6  = { 33 c5 89 45 fc 8b 45 08 53 56 ff 75 0c 33 db }
    $pattern_7  = { e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 01 75 05 e8 ?? ?? ?? ?? }
    $pattern_8  = { 53 53 8d 85 f4 fa ff ff 50 }
    $pattern_9  = { 68 ?? ?? ?? ?? 53 50 e8 ?? ?? ?? ?? 83 c4 24 }
    $pattern_10 = { 48 8b 4c 24 20 8b 04 01 8b 4c 24 08 33 c8 8b c1 89 44 24 08 }
    $pattern_11 = { 48 8d 4d 97 e8 ?? ?? ?? ?? 4c 8d 9c 24 d0 00 00 00 41 8b c7 49 8b 5b 20 49 8b 73 28 49 8b 7b 30 }
    $pattern_12 = { bd 08 00 00 00 85 d2 74 59 ff cf 4d 85 ed }
    $pattern_13 = { 41 83 c9 ff 33 d2 ff 15 ?? ?? ?? ?? 4c 63 c0 49 83 f8 ff }
    $pattern_14 = { 49 c1 e0 02 e8 ?? ?? ?? ?? 03 f3 4d 8d 34 9e 3b f5 7d 13 }
    $pattern_15 = { 75 2c 4c 8d 45 af 48 8d 55 af 48 8d 4d 27 }

  condition:
    7 of them and filesize < 696320
}