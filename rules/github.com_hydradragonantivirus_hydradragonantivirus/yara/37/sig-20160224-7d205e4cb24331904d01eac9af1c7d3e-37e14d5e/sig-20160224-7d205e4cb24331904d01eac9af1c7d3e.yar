rule sig_20160224_7d205e4cb24331904d01eac9af1c7d3e {
  meta:
    description = "datamaliciousorder - file 20160224_7d205e4cb24331904d01eac9af1c7d3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51a36e6cb3d9bedd1668f06b3911e13b44ffb1ad507d8db2d2af0d6b21bc91d1"

  strings:
    $s1 = "0079s\\u0074\\u0065\\u006D\\u002F\\u006C\\u006F\\u0067\\u0073\\u002F\\u0038\\u0037\\u0068\\u0037\\u0035\\u0034', false);" fullword ascii
    $s2 = "var SeMMdP= this['\\u0041\\u0063\\u0074iv\\u0065\\u0058\\u004F\\u0062\\u006A\\u0065\\u0063\\u0074'];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}