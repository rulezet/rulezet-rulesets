rule DITEKSHEN_INDICATOR_SUSPICIOUS_Enablesmbv1: FILE {
  meta:
    description = "Detects binaries with PowerShell command enabling SMBv1"
    author      = "ditekSHen"
    id          = "cb3b43f3-8f45-5e4e-8e5e-9bfb89e842d3"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1991-L1999"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "68eb41d843b39e784d99153607c1deecdb5258cdbf641e2dd177c364847d85b1"
    score       = 40
    quality     = 43
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and 1 of them
}