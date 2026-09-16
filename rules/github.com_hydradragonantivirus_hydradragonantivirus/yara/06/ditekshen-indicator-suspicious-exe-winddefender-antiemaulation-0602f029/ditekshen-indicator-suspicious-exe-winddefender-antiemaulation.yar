rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Winddefender_Antiemaulation: FILE {
  meta:
    description = "Detects executables containing potential Windows Defender anti-emulation checks"
    author      = "ditekSHen"
    id          = "e7dca0e6-060b-5394-afc5-b3705a51d934"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1249-L1258"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "76f8a532a59c2a7fcd45d9f9aed3ea2020889228c81410445728f42b6b9d891e"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "JohnDoe" fullword ascii wide
    $s2 = "HAL9TH" fullword ascii wide

  condition:
    uint16(0) == 0x5a4d and all of them
}