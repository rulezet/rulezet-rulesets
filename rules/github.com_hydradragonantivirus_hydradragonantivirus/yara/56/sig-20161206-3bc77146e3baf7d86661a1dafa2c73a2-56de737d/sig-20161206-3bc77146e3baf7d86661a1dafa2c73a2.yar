rule sig_20161206_3bc77146e3baf7d86661a1dafa2c73a2 {
  meta:
    description = "datamaliciousorder - file 20161206_3bc77146e3baf7d86661a1dafa2c73a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ad89ce3d5f1d1b761cd215cf14c2dfdc5a756fb0127e37e58db53faeb49e204"

  strings:
    $s1 = "var vXYy7 = new Function(\"s\", '{var vUp0 = new Date();vUp0[\"setUTCFullYear\"](\"2003\");if (vUp0.getUTCFullYear().toString(10" ascii
    $s2 = "var vXYy7 = new Function(\"s\", '{var vUp0 = new Date();vUp0[\"setUTCFullYear\"](\"2003\");if (vUp0.getUTCFullYear().toString(10" ascii
    $s3 = "function vRu8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vHz1 = s.split(\"##\"); return vHz1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}