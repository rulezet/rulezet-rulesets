rule sig_20160302_ce2ea4d0f27d0637e658173d1c547b5e {
  meta:
    description = "datamaliciousorder - file 20160302_ce2ea4d0f27d0637e658173d1c547b5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3c0f7327250e348b50fd913c2a3328f61882ac2b66169cdd29e549db6fdfab"

  strings:
    $s1 = "            return c((n >>> 10) + 55296) + c((1023 & n) + 56320);" fullword ascii
    $s2 = "var astringentIWL = function(r) {" fullword ascii
    $s3 = "var lodeezo = function() {" fullword ascii
    $s4 = "    var s = String[\"fr\" + \"om\" + \"C\" + \"harCode\"];" fullword ascii
    $s5 = "        VERSION: n," fullword ascii
    $s6 = "        decode: b," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}