rule sig_20160302_4a75af6c0adb0e1ffacebb034a46997f {
  meta:
    description = "datamaliciousorder - file 20160302_4a75af6c0adb0e1ffacebb034a46997f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4466e88c3505a4ed03f8ee8edf81ee315a463b22667900ac57ab85c2b316f95f"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var daisIPb = function(r) {" fullword ascii
    $s3 = "var mienGw5 = function() {" fullword ascii
    $s4 = "    var v = String[\"f\" + \"r\" + \"o\" + \"m\" + \"Ch\" + \"arCode\"];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}