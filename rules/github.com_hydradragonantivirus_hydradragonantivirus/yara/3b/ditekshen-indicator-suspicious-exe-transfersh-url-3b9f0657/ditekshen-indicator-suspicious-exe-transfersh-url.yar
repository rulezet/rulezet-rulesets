rule DITEKSHEN_INDICATOR_SUSPICIOUS_EXE_Transfersh_URL: FILE {
  meta:
    description = "Detects files referencing the transfer.sh file sharing website"
    author      = "ditekSHen"
    id          = "15c6ba05-199d-52ba-98bf-7e8a8eda0295"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L2415-L2423"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "45b16f853bcd9c492468bc478d0a7eeecd261ae47b5b00bb1e4a79788fdec7a1"
    score       = 40
    quality     = 43
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "//transfer.sh/get/" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and 1 of them
}