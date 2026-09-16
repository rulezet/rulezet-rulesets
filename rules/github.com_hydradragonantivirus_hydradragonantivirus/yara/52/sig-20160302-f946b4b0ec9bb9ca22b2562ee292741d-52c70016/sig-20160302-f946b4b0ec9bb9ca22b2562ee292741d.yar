rule sig_20160302_f946b4b0ec9bb9ca22b2562ee292741d {
  meta:
    description = "datamaliciousorder - file 20160302_f946b4b0ec9bb9ca22b2562ee292741d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61645bf6ca59dc5228b0ce9b7688c18429ee02698b1763a7124c984dd973cfa5"

  strings:
    $s1 = "            return i((t >>> 10) + 55296) + i((1023 & t) + 56320);" fullword ascii
    $s2 = "            return a < 128 ? r : a < 2048 ? i(192 | a >>> 6) + i(128 | 63 & a) : i(224 | a >>> 12 & 15) + i(128 | a >>> 6 & 63) " ascii
    $s3 = "            return a < 128 ? r : a < 2048 ? i(192 | a >>> 6) + i(128 | 63 & a) : i(224 | a >>> 12 & 15) + i(128 | a >>> 6 & 63) " ascii
    $s4 = "            return i(240 | a >>> 18 & 7) + i(128 | a >>> 12 & 63) + i(128 | a >>> 6 & 63) + i(128 | 63 & a);" fullword ascii
    $s5 = "        return WScript[a](r);" fullword ascii
    $s6 = "var improvidentvLU = function() {" fullword ascii
    $s7 = "var avaricecxN = function(r) {" fullword ascii
    $s8 = "    var l = String[\"f\" + \"r\" + \"om\" + \"Ch\" + \"a\" + \"rCode\"];" fullword ascii
    $s9 = "        VERSION: t," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}