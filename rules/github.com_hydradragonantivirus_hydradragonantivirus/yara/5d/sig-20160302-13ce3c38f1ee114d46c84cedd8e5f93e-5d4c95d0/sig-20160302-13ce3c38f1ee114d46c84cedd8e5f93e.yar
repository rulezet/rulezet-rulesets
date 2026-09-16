rule sig_20160302_13ce3c38f1ee114d46c84cedd8e5f93e {
  meta:
    description = "datamaliciousorder - file 20160302_13ce3c38f1ee114d46c84cedd8e5f93e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d98944b4a2483ccd9d2247549392e33fd1a7d7ce1a2e990560b1813dbee65c69"

  strings:
    $s1 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s2 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s3 = "            return u(240 | t >>> 18 & 7) + u(128 | t >>> 12 & 63) + u(128 | t >>> 6 & 63) + u(128 | 63 & t);" fullword ascii
    $s4 = "            return u((e >>> 10) + 55296) + u((1023 & e) + 56320);" fullword ascii
    $s5 = "var swerveteF = function() {" fullword ascii
    $s6 = "var tyroydB = function(r) {" fullword ascii
    $s7 = "    var f = String[\"fro\" + \"mC\" + \"har\" + \"Code\"];" fullword ascii
    $s8 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}