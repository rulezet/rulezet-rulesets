rule sig_20160302_d4970e415bba096f18ab311429cd9ff3 {
  meta:
    description = "datamaliciousorder - file 20160302_d4970e415bba096f18ab311429cd9ff3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9ed3f2ed438dddc8c945addaadde11d384ea1859a6f9dae88fd655ab2179cd"

  strings:
    $s1 = "            return i(240 | t >>> 18 & 7) + i(128 | t >>> 12 & 63) + i(128 | t >>> 6 & 63) + i(128 | 63 & t);" fullword ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s4 = "            return i((e >>> 10) + 55296) + i((1023 & e) + 56320);" fullword ascii
    $s5 = "var courtAay = function() {" fullword ascii
    $s6 = "    var v = String[\"fro\" + \"m\" + \"Ch\" + \"arCode\"];" fullword ascii
    $s7 = "        decode: b," fullword ascii
    $s8 = "var explicateS6W = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}