rule DITEKSHEN_INDICATOR_PDF_Ipdropper: FILE {
  meta:
    description = "Detects PDF documents with Action and URL pointing to direct IP address"
    author      = "ditekSHen"
    id          = "83368671-f1ec-5b09-9d55-6e45e576ebdb"
    date        = "2024-02-22"
    modified    = "2024-02-22"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_office.yar#L729-L738"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "be37ee7ef5d8c980483f31bf5667c2dad4321d662be05c495ec6755362d33fd6"
    score       = 60
    quality     = 35
    tags        = "FILE"

  strings:
    $s1 = "Type /Action\r\n/S /URI\r\n"
    $s2 = /\/URI \(http(s)?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}\// ascii

  condition:
    uint32(0) == 0x46445025 and all of them
}