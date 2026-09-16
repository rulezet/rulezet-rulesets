rule sig_20161206_df1815fc0c21b019fdd2c5dc6c028e45 {
  meta:
    description = "datamaliciousorder - file 20161206_df1815fc0c21b019fdd2c5dc6c028e45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca657665a6fb47a4b10d5162fe2dcc1b6ad4881475486d29447fd2dc2afb1c66"

  strings:
    $s1 = "var vLx8 = new Function(\"s\", '{var vVf1 = new Date();vVf1[\"setUTCFullYear\"](\"2003\");if (vVf1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vLx8 = new Function(\"s\", '{var vVf1 = new Date();vVf1[\"setUTCFullYear\"](\"2003\");if (vVf1.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vWAw1 = s.split(\"##\"); return vWAw1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYYg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}