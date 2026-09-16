rule sig_20161206_dabe3da78ff678b2341fe9ec8b8d832c {
  meta:
    description = "datamaliciousorder - file 20161206_dabe3da78ff678b2341fe9ec8b8d832c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42ab72310d7ba54ac1d0b29fafb8b81f63cb2b731add8394d8459d2dc5d88295"

  strings:
    $s1 = "var vDEs8 = new Function(\"s\", '{var vDIt8 = new Date();vDIt8[\"setUTCFullYear\"](\"2003\");if (vDIt8.getUTCFullYear().toString" ascii
    $s2 = "var vDEs8 = new Function(\"s\", '{var vDIt8 = new Date();vDIt8[\"setUTCFullYear\"](\"2003\");if (vDIt8.getUTCFullYear().toString" ascii
    $s3 = "function vKMa0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vFm3 = s.split(\"##\"); return vFm3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}