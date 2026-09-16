rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_B64_Artifacts: FILE {
  meta:
    description = "Detects executables embedding bas64-encoded APIs, command lines, registry keys, etc."
    author      = "ditekSHen"
    id          = "b76ba291-6af5-5800-a280-c04c84cc3f29"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1310-L1321"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "35a7a9c0722d8bd174b272c659e62db3e9f41483dc3a9bf5f339b9066ed06c57"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA" ascii wide
    $s2 = "L2Mgc2NodGFza3MgL2" ascii wide
    $s3 = "QW1zaVNjYW5CdWZmZXI" ascii wide
    $s4 = "VmlydHVhbFByb3RlY3Q" ascii wide

  condition:
    uint16(0) == 0x5a4d and 2 of them
}