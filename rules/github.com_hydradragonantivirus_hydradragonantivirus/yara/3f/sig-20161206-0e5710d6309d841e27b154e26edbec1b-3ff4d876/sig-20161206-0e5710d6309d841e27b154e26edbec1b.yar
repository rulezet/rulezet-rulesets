rule sig_20161206_0e5710d6309d841e27b154e26edbec1b {
  meta:
    description = "datamaliciousorder - file 20161206_0e5710d6309d841e27b154e26edbec1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac11341765777962d4b9b8333abe96a3a2ed54a9aa9b83031d73cc6e83bf096"

  strings:
    $s1 = "var vYEl8 = new Function(\"s\", '{var vVDp2 = new Date();vVDp2[\"setUTCFullYear\"](\"2003\");if (vVDp2.getUTCFullYear().toString" ascii
    $s2 = "var vYEl8 = new Function(\"s\", '{var vVDp2 = new Date();vVDp2[\"setUTCFullYear\"](\"2003\");if (vVDp2.getUTCFullYear().toString" ascii
    $s3 = "function vEm7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vSl1 = s.split(\"##\"); return vSl1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}