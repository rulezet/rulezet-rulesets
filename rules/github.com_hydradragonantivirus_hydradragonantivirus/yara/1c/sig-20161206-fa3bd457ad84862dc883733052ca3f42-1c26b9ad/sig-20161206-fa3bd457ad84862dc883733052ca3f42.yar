rule sig_20161206_fa3bd457ad84862dc883733052ca3f42 {
  meta:
    description = "datamaliciousorder - file 20161206_fa3bd457ad84862dc883733052ca3f42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a81056425b563d1e61ba4281b62ed3fe0f320f818f805aaa7fd90e913249640c"

  strings:
    $s1 = "var vECf7 = new Function(\"s\", '{var vKu8 = new Date();vKu8[\"setUTCFullYear\"](\"2003\");if (vKu8.getUTCFullYear().toString(10" ascii
    $s2 = "var vECf7 = new Function(\"s\", '{var vKu8 = new Date();vKu8[\"setUTCFullYear\"](\"2003\");if (vKu8.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vSZk5 = s.split(\"##\"); return vSZk5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vJBk2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}