rule sig_20161207_e85ab4e59b5d25985c8d21b392bee26c {
  meta:
    description = "datamaliciousorder - file 20161207_e85ab4e59b5d25985c8d21b392bee26c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fb86f61105c3c1777915523d663e809c74c22f9300e8619e40ad8100e0b1038"

  strings:
    $s1 = "var vVq3 = new Function(\"vEFg2\", '{var vNw4 = new Date();vNw4[\"setUTCFullYear\"](\"2003\");if (vNw4.getUTCFullYear().toString" ascii
    $s2 = "var vVq3 = new Function(\"vEFg2\", '{var vNw4 = new Date();vNw4[\"setUTCFullYear\"](\"2003\");if (vNw4.getUTCFullYear().toString" ascii
    $s3 = "var vEq5 = new Function(\"vEFg2\", '{return vEFg2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vVDa5 = vEFg2.split(\"###\"); return vVDa5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}