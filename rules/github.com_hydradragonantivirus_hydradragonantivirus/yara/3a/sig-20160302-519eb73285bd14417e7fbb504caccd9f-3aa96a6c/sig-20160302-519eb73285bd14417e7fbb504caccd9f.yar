rule sig_20160302_519eb73285bd14417e7fbb504caccd9f {
  meta:
    description = "datamaliciousorder - file 20160302_519eb73285bd14417e7fbb504caccd9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d30133966a21ea56cdce18dd519de4efacd6b985b25e4ee53383c5f604df074a"

  strings:
    $s1 = "var hackneyedtMu = function() {" fullword ascii
    $s2 = "            return c((n >>> 10) + 55296) + c((1023 & n) + 56320);" fullword ascii
    $s3 = "var hoodwinkSYC = function(r) {" fullword ascii
    $s4 = "    var f = String[\"f\" + \"r\" + \"o\" + \"m\" + \"CharCode\"];" fullword ascii
    $s5 = "        VERSION: n," fullword ascii
    $s6 = "        decode: A," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}