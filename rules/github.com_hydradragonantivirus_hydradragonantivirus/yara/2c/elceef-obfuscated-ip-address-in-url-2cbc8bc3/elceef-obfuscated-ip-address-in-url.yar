rule ELCEEF_Obfuscated_IP_Address_In_URL {
  meta:
    description = "Detects hexadecimal and octal IP address representations in URL"
    author      = "marcin@ulikowski.pl"
    id          = "f2ebf5f7-5446-5eaa-8e30-90d08b8616d9"
    date        = "2020-09-17"
    modified    = "2024-03-04"
    reference   = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/evasive-urls-in-spam/"
    source_url  = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/rules/Obfuscated_IPAddr_URL.yara#L1-L17"
    license_url = "https://github.com/elceef/yara-rulz/blob/ff4396e33ef3e2561191a2193902d1d809a7fa3d/LICENSE"
    logic_hash  = "ab2a2a3a56e6eed9f4a3a8f994c89a167f00b86ce442820c81d8ee673b0ab85c"
    score       = 75
    quality     = 65
    tags        = ""

  strings:
    $ = /="?http:\/\/0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.0[0-7]{1,3}\.?\// nocase ascii wide
    $ = /="?http:\/\/0x[0-9a-f]{8}\.?\// nocase ascii wide
    $ = /="?http:\/\/0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.0x[0-9a-f]{2}\.?\// nocase ascii wide
    $ = /="?http:\/\/[0-9]{8,10}\.?\// nocase ascii wide

  condition:
    any of them
}