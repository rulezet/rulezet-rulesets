rule sig_20170504_5504352d8fd4cfaeaeb788cbecf4ac2b {
  meta:
    description = "datamaliciousorder - file 20170504_5504352d8fd4cfaeaeb788cbecf4ac2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41df91ba56e57a942ace94db5193ddad79c69eb4c9cca9b698d676b8bd61c4d7"

  strings:
    $s1 = "this[\"\\145\\u0076\\u0061\\u006c\"](\"\\156\\x65w\\x20\\101\\u0063t\\151v\\x65X\\x4fb\\x6a\\145\\143t\\x28\\x22\\x57\\u0053c\\u" ascii
    $s2 = "this[\"\\145\\u0076\\u0061\\u006c\"](\"\\156\\x65w\\x20\\101\\u0063t\\151v\\x65X\\x4fb\\x6a\\145\\143t\\x28\\x22\\x57\\u0053c\\u" ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}