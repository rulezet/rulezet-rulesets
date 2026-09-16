rule sig_20161206_c9c4da358e675901ecebdf43bb7da7e9 {
  meta:
    description = "datamaliciousorder - file 20161206_c9c4da358e675901ecebdf43bb7da7e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d40086e58f739c6d6e599fed0776d9afe922e1d002d1fd43b0828146c66a9a3"

  strings:
    $s1 = "var vAFm9 = new Function(\"s\", '{var vCBw7 = new Date();vCBw7[\"setUTCFullYear\"](\"2003\");if (vCBw7.getUTCFullYear().toString" ascii
    $s2 = "var vAFm9 = new Function(\"s\", '{var vCBw7 = new Date();vCBw7[\"setUTCFullYear\"](\"2003\");if (vCBw7.getUTCFullYear().toString" ascii
    $s3 = "function vXr6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vYj3 = s.split(\"##\"); return vYj3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}