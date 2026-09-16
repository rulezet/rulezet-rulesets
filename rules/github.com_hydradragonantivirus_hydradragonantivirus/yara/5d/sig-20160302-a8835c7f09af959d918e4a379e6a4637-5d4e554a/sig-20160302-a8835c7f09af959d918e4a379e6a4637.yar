rule sig_20160302_a8835c7f09af959d918e4a379e6a4637 {
  meta:
    description = "datamaliciousorder - file 20160302_a8835c7f09af959d918e4a379e6a4637.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6faef06771fc174656474dd248aa53c93f1c104499af917ee8cdd44626b4986c"

  strings:
    $s1 = "            return o(240 | t >>> 18 & 7) + o(128 | t >>> 12 & 63) + o(128 | t >>> 6 & 63) + o(128 | 63 & t);" fullword ascii
    $s2 = "            return o((e >>> 10) + 55296) + o((1023 & e) + 56320);" fullword ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? o(192 | t >>> 6) + o(128 | 63 & t) : o(224 | t >>> 12 & 15) + o(128 | t >>> 6 & 63) " ascii
    $s4 = "            return t < 128 ? r : t < 2048 ? o(192 | t >>> 6) + o(128 | 63 & t) : o(224 | t >>> 12 & 15) + o(128 | t >>> 6 & 63) " ascii
    $s5 = "var multitudeHlc = function() {" fullword ascii
    $s6 = "var interdictFLX = function(r) {" fullword ascii
    $s7 = "    var o = String[\"f\" + \"ro\" + \"m\" + \"Ch\" + \"a\" + \"rCode\"];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}