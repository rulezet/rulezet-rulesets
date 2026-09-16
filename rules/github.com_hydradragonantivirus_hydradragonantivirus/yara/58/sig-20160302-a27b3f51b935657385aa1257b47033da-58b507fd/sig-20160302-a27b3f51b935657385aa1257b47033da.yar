rule sig_20160302_a27b3f51b935657385aa1257b47033da {
  meta:
    description = "datamaliciousorder - file 20160302_a27b3f51b935657385aa1257b47033da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cb2c0eb71580b22a410c83701499e6e7b92517e36be5dbd2e57c166c04de37f"

  strings:
    $s1  = "            return c((t >>> 10) + 55296) + c((1023 & t) + 56320);" fullword ascii
    $s2  = "            return e < 128 ? r : e < 2048 ? c(192 | e >>> 6) + c(128 | 63 & e) : c(224 | e >>> 12 & 15) + c(128 | e >>> 6 & 63) " ascii
    $s3  = "            return e < 128 ? r : e < 2048 ? c(192 | e >>> 6) + c(128 | 63 & e) : c(224 | e >>> 12 & 15) + c(128 | e >>> 6 & 63) " ascii
    $s4  = "            return c(240 | e >>> 18 & 7) + c(128 | e >>> 12 & 63) + c(128 | e >>> 6 & 63) + c(128 | 63 & e);" fullword ascii
    $s5  = "        return WScript[e](r);" fullword ascii
    $s6  = "var gruelW1E = function(r) {" fullword ascii
    $s7  = "var redoubtablecXN = function() {" fullword ascii
    $s8  = "    var u = String[\"f\" + \"ro\" + \"mC\" + \"ha\" + \"rC\" + \"ode\"];" fullword ascii
    $s9  = "        VERSION: t," fullword ascii
    $s10 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}