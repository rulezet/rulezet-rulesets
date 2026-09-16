rule sig_20161207_903f0bcf74ac1b52778a7bc37092f598 {
  meta:
    description = "datamaliciousorder - file 20161207_903f0bcf74ac1b52778a7bc37092f598.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "647c7312d2a44543643e7f8f3a31e0fc444133dc00af7f5567f2d5f592cc5d05"

  strings:
    $s1 = "var vHIe4 = new Function(\"vIt1\", '{var vJy2 = new Date();vJy2[\"setUTCFullYear\"](\"2003\");if (vJy2.getUTCFullYear().toString" ascii
    $s2 = "var vHIe4 = new Function(\"vIt1\", '{var vJy2 = new Date();vJy2[\"setUTCFullYear\"](\"2003\");if (vJy2.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vNs9 = vIt1.split(\"###\"); return vNs9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vROg8 = new Function(\"vIt1\", '{return vIt1.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}