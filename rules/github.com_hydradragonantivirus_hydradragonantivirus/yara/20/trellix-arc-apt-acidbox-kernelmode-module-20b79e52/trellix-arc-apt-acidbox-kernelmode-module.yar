rule TRELLIX_ARC_APT_Acidbox_Kernelmode_Module: KERNELDRIVER FILE {
  meta:
    description    = "Rule to detect the kernel mode component of AcidBox"
    author         = "Marc Rivero | McAfee ATR Team"
    id             = "80b60307-5431-5f21-9e6f-06adaab0519d"
    date           = "2020-07-24"
    modified       = "2020-08-14"
    reference      = "https://github.com/advanced-threat-research/Yara-Rules/"
    source_url     = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/APT/APT_acidbox.yar#L1-L32"
    license_url    = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
    logic_hash     = "e39da89d0da22115ac7889bc73ff183973a6c5334e304df955362bde76694d42"
    score          = 75
    quality        = 70
    tags           = "KERNELDRIVER, FILE"
    rule_version   = "v1"
    malware_type   = "kerneldriver"
    malware_family = "Rootkit:W32/Acidbox"
    actor_type     = "APT"
    actor_group    = "Turla"
    hash1          = "3ef071e0327e7014dd374d96bed023e6c434df6f98cce88a1e7335a667f6749d"

  strings:
    $pattern_0 = { 89 7c 24 34 89 78 b8 8d 5f 28 44 8b c3 33 d2 }
    $pattern_1 = { 4c 8d 84 24 70 01 00 00 48 8d 94 24 18 01 00 00 49 8b cf e8 ?? ?? ?? ?? 8b d8 89 44 24 60 }
    $pattern_2 = { 4c 8b f1 49 d1 eb 45 85 c9 0f 88 a2 00 00 00 44 0f b7 17 49 8b d0 }
    $pattern_3 = { ff 15 ?? ?? ?? ?? 4c 8d 9c 24 80 00 00 00 49 8b 5b 10 49 8b 73 18 49 8b 7b 20 4d 8b 73 28 49 8b e3 }
    $pattern_4 = { 33 d2 41 b8 ?? ?? ?? ?? 89 5c 24 20 e8 ?? ?? ?? ?? }
    $pattern_5 = { 89 5c 24 20 48 85 ff 0f 84 24 01 00 00 44 0f 20 c0 84 c0 0f 85 18 01 00 00 }
    $pattern_6 = { 85 f6 0f 84 69 fd ff ff 48 8d 84 24 c8 01 00 00 41 b9 ?? ?? ?? ?? }
    $pattern_7 = { 89 4c 24 04 75 0a ff c7 89 3c 24 41 ff c3 eb cb 85 c9 }
    $pattern_8 = { 48 8b 5c 24 50 48 8b 74 24 58 48 8b 7c 24 60 48 83 c4 30 }
    $pattern_9 = { 33 d2 48 8b 4c 24 28 e8 ?? ?? ?? ?? 44 8b 84 24 50 04 00 00 45 03 c0 4c 8d 8c 24 50 04 00 00 48 8b d7 }

  condition:
    7 of them and filesize < 78848
}