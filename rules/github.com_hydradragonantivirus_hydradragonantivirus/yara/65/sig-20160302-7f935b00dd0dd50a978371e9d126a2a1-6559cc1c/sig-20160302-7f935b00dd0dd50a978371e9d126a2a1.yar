rule sig_20160302_7f935b00dd0dd50a978371e9d126a2a1 {
  meta:
    description = "datamaliciousorder - file 20160302_7f935b00dd0dd50a978371e9d126a2a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f51a9cb581fb221c08c5a70a9d6d2c7b1e487054219aab4aa2050efa9a7d3e90"

  strings:
    $s1 = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s2 = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s3 = "            return u(240 | e >>> 18 & 7) + u(128 | e >>> 12 & 63) + u(128 | e >>> 6 & 63) + u(128 | 63 & e);" fullword ascii
    $s4 = "            return u((a >>> 10) + 55296) + u((1023 & a) + 56320);" fullword ascii
    $s5 = "        return WScript[e](r);" fullword ascii
    $s6 = "var evidentlsa = function() {" fullword ascii
    $s7 = "    var i = String[\"fr\" + \"om\" + \"Ch\" + \"ar\" + \"C\" + \"ode\"];" fullword ascii
    $s8 = "        VERSION: a," fullword ascii
    $s9 = "var cadaverousHxn = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}