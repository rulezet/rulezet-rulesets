rule sig_20150827_eb78214602eabe3c0c5933318a1a7bc6 {
  meta:
    description = "datamaliciousorder - file 20150827_eb78214602eabe3c0c5933318a1a7bc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53dc6ef67aa3dbfe180d3a062ac886a476b002576f50305989ec70d0f5421598"

  strings:
    $s1 = "var key = 'amlZPi';var b = '(,\\x18\\x16\\x15#\\x00\\x1c!8\\x05\\x1f\\x18\\x0fTzmIC\\x05^lrRlg\\x0a/>\\x0a\\x15\\x04\\x034p  \\x" ascii
    $s2 = "t(kGIjv6) ^ key.charCodeAt(kGIjv7)), kGIjv7++, kGIjv7 == key.length && (kGIjv7 = 0);print(kGIjv5);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}