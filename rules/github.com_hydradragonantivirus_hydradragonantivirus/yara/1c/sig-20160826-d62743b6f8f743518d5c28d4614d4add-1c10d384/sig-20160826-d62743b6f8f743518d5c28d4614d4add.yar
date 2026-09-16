rule sig_20160826_d62743b6f8f743518d5c28d4614d4add {
  meta:
    description = "datamaliciousorder - file 20160826_d62743b6f8f743518d5c28d4614d4add.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6255891a6fa2c724b56fd20dd68f480c92dbb9ce006158a5f8255b397f24e1fe"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}