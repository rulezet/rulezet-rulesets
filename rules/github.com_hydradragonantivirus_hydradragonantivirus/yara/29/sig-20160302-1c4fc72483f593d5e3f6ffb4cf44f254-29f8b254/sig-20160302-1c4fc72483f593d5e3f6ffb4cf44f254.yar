rule sig_20160302_1c4fc72483f593d5e3f6ffb4cf44f254 {
  meta:
    description = "datamaliciousorder - file 20160302_1c4fc72483f593d5e3f6ffb4cf44f254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e68fb8feb90c41f6f9a3b8d60b666832b7e703138d5db6e641d4766f6ac4f8a1"

  strings:
    $s1 = "            return i(240 | t >>> 18 & 7) + i(128 | t >>> 12 & 63) + i(128 | t >>> 6 & 63) + i(128 | 63 & t);" fullword ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? i(192 | t >>> 6) + i(128 | 63 & t) : i(224 | t >>> 12 & 15) + i(128 | t >>> 6 & 63) " ascii
    $s4 = "            return i((n >>> 10) + 55296) + i((1023 & n) + 56320);" fullword ascii
    $s5 = "var unfalteringvPR = function(r) {" fullword ascii
    $s6 = "var hoodwinkhOh = function() {" fullword ascii
    $s7 = "    var f = String[\"fr\" + \"o\" + \"mC\" + \"ha\" + \"rC\" + \"ode\"];" fullword ascii
    $s8 = "        VERSION: n," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}