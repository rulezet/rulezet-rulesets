rule sig_20160224_191f0060d9b8d7a0f79ec16cd19be528 {
  meta:
    description = "datamaliciousorder - file 20160224_191f0060d9b8d7a0f79ec16cd19be528.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2244b3ac2b4de56e6c1296065b72f13df653934da11aace131d6a61e4e73cd71"

  strings:
    $s1 = "0068\\u0037\\u0035\\u0034', false);" fullword ascii
    $s2 = "var pKPBTHC= this['\\u0041\\u0063\\u0074\\u0069\\u0076\\u0065\\u0058O\\u0062j\\u0065\\u0063\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}