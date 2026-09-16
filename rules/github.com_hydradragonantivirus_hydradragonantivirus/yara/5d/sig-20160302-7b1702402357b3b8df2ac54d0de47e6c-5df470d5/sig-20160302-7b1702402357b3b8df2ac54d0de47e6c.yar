rule sig_20160302_7b1702402357b3b8df2ac54d0de47e6c {
  meta:
    description = "datamaliciousorder - file 20160302_7b1702402357b3b8df2ac54d0de47e6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35a8a327b34db77da9387d1045e37b7ef83c496897ce7d70026ab8da988b93c1"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var yieldF9g = function(r) {" fullword ascii
    $s3 = "var exertiontvN = function() {" fullword ascii
    $s4 = "    var g = String[\"f\" + \"ro\" + \"m\" + \"C\" + \"harCode\"];" fullword ascii
    $s5 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}