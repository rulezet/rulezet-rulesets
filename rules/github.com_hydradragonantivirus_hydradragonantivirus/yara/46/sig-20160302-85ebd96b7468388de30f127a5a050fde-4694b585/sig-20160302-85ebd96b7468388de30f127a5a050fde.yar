rule sig_20160302_85ebd96b7468388de30f127a5a050fde {
  meta:
    description = "datamaliciousorder - file 20160302_85ebd96b7468388de30f127a5a050fde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da2f51faa857a4c484266a940396dc9b951f1484ef303e3199414163d1b08521"

  strings:
    $s1 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s3 = "            return u(240 | t >>> 18 & 7) + u(128 | t >>> 12 & 63) + u(128 | t >>> 6 & 63) + u(128 | 63 & t);" fullword ascii
    $s4 = "            return u((a >>> 10) + 55296) + u((1023 & a) + 56320);" fullword ascii
    $s5 = "var tractSw6 = function(r) {" fullword ascii
    $s6 = "var devolveznl = function() {" fullword ascii
    $s7 = "    var i = String[\"fr\" + \"o\" + \"mC\" + \"ha\" + \"rCode\"];" fullword ascii
    $s8 = "        VERSION: a," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}