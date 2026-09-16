rule sig_20161206_c510264c468f4e73d349ca50f137daff {
  meta:
    description = "datamaliciousorder - file 20161206_c510264c468f4e73d349ca50f137daff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2d575c46ea9a36536b9a68cb50b4b47c1bd733f82d97d79fcc4701c9af17838"

  strings:
    $s1 = "var vLRw7 = new Function(\"s\", '{var vHWg8 = new Date();vHWg8[\"setUTCFullYear\"](\"2003\");if (vHWg8.getUTCFullYear().toString" ascii
    $s2 = "var vLRw7 = new Function(\"s\", '{var vHWg8 = new Date();vHWg8[\"setUTCFullYear\"](\"2003\");if (vHWg8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vUk6 = s.split(\"##\"); return vUk6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSh1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}