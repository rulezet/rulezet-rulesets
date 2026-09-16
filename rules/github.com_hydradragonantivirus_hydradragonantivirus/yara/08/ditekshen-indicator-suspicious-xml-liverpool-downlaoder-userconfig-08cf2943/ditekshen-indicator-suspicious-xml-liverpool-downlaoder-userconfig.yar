rule DITEKSHEN_INDICATOR_SUSPICIOUS_XML_Liverpool_Downlaoder_Userconfig: FILE {
  meta:
    description = "Detects XML files associated with 'Liverpool' downloader containing encoded executables"
    author      = "ditekSHen"
    id          = "b5840af5-a285-53f4-bac7-07821e740089"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1227-L1236"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "8140c29eb54d8c8786b268d5241fcd221a5fb95433bc1038a7f23295afe8c9b8"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "<configSections>" ascii nocase
    $s2 = "<value>77 90" ascii nocase

  condition:
    uint32(0) == 0x6d783f3c and all of them
}