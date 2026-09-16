rule sig_20160302_08211a015fb54575a9df9d34a4bdf06f {
  meta:
    description = "datamaliciousorder - file 20160302_08211a015fb54575a9df9d34a4bdf06f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd978c2c876e90bd3fb11385566ea8aec34d5791711deb6e275fb304ccecd136"

  strings:
    $s1 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s2 = "            return u((n >>> 10) + 55296) + u((1023 & n) + 56320);" fullword ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s4 = "            return u(240 | t >>> 18 & 7) + u(128 | t >>> 12 & 63) + u(128 | t >>> 6 & 63) + u(128 | 63 & t);" fullword ascii
    $s5 = "var admonishjUQ = function(r) {" fullword ascii
    $s6 = "var audaciousEvj = function() {" fullword ascii
    $s7 = "    var d = String[\"f\" + \"r\" + \"o\" + \"m\" + \"C\" + \"harCode\"];" fullword ascii
    $s8 = "        VERSION: n," fullword ascii
    $s9 = "        decode: C," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}