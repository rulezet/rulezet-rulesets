rule sig_20161206_2cb965fbb490d85ac996f00e43fd9381 {
  meta:
    description = "datamaliciousorder - file 20161206_2cb965fbb490d85ac996f00e43fd9381.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f11e360d9434e73b982e8929056778bf74223a62cc014ae9b6a9898cb45f4074"

  strings:
    $s1 = "var vSd2 = new Function(\"s\", '{var vTi8 = new Date();vTi8[\"setUTCFullYear\"](\"2003\");if (vTi8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vSd2 = new Function(\"s\", '{var vTi8 = new Date();vTi8[\"setUTCFullYear\"](\"2003\");if (vTi8.getUTCFullYear().toString(10)" ascii
    $s3 = "function vIKz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vJr1 = s.split(\"##\"); return vJr1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}