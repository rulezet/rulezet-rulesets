rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Go_Golazagne: FILE {
  meta:
    description = "Detects Go executables using GoLazagne"
    author      = "ditekSHen"
    id          = "3b54892d-8015-518c-af0b-03ddd65478f6"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1545-L1554"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "9618f8a6eb9a5db01b7a58a469309220b1e22afe928006d642e5404380f312f1"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "/goLazagne/" ascii nocase
    $s2 = "Go build ID:" ascii

  condition:
    uint16(0) == 0x5a4d and all of them
}