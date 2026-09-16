rule sig_20161206_af7e5068ad2044b2ead5dc001b360804 {
  meta:
    description = "datamaliciousorder - file 20161206_af7e5068ad2044b2ead5dc001b360804.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0411e4eb15e4f1d34a0fa461f65573b245e5e58f11a3ef0e26a8e3d939c0949f"

  strings:
    $s1 = "var vXHd1 = new Function(\"s\", '{var vIo9 = new Date();vIo9[\"setUTCFullYear\"](\"2003\");if (vIo9.getUTCFullYear().toString(10" ascii
    $s2 = "var vXHd1 = new Function(\"s\", '{var vIo9 = new Date();vIo9[\"setUTCFullYear\"](\"2003\");if (vIo9.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vHu3 = s.split(\"##\"); return vHu3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVp4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}