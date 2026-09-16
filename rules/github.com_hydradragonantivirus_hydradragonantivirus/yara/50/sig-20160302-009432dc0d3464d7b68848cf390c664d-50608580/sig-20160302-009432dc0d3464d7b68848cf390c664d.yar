rule sig_20160302_009432dc0d3464d7b68848cf390c664d {
  meta:
    description = "datamaliciousorder - file 20160302_009432dc0d3464d7b68848cf390c664d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79f855d2000a825a9283230479f4914c66927e4d0229c6fa187e6c74d00efc54"

  strings:
    $s1 = "            return i(240 | t >>> 18 & 7) + i(128 | t >>> 12 & 63) + i(128 | t >>> 6 & 63) + i(128 | 63 & t);" fullword ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s4 = "            return i((e >>> 10) + 55296) + i((1023 & e) + 56320);" fullword ascii
    $s5 = "var reticentrdn = function(r) {" fullword ascii
    $s6 = "var acrimonythm = function() {" fullword ascii
    $s7 = "    var s = String[\"fr\" + \"o\" + \"m\" + \"Ch\" + \"arCode\"];" fullword ascii
    $s8 = "        decode: m," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}