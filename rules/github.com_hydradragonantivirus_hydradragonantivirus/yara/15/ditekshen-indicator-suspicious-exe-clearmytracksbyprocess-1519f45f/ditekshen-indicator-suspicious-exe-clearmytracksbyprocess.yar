rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Clearmytracksbyprocess: FILE {
  meta:
    description = "Detects executables calling ClearMyTracksByProcess"
    author      = "ditekSHen"
    id          = "d548cf61-ffb7-5a21-9b76-246f8ffb6ad4"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1270-L1278"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "970bdf2cfebc5196204087de134b9d2f032d8074cacbb3b9cc2c859aab3a95fc"
    score       = 40
    quality     = 43
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "InetCpl.cpl,ClearMyTracksByProcess" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and any of them
}