rule sig_20161206_e148892c0de2b8c67343e4072bb48089 {
  meta:
    description = "datamaliciousorder - file 20161206_e148892c0de2b8c67343e4072bb48089.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dba079782e9514b2196e2f3bc99d729826310f1f5a953bfa6f3c086a41f89b11"

  strings:
    $s1 = "var vFk3 = new Function(\"s\", '{var vXQh8 = new Date();vXQh8[\"setUTCFullYear\"](\"2003\");if (vXQh8.getUTCFullYear().toString(" ascii
    $s2 = "var vFk3 = new Function(\"s\", '{var vXQh8 = new Date();vXQh8[\"setUTCFullYear\"](\"2003\");if (vXQh8.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vUGo9 = s.split(\"##\"); return vUGo9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVu9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}