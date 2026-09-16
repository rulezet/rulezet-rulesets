rule sig_20161206_a57206502177a9acccbdc7c5f52888a4 {
  meta:
    description = "datamaliciousorder - file 20161206_a57206502177a9acccbdc7c5f52888a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5dedd868848430e6b7a56a932a2284e4ec70be4d57152f1432663f158430da9"

  strings:
    $s1 = "var vDJi5 = new Function(\"s\", '{var vEYq3 = new Date();vEYq3[\"setUTCFullYear\"](\"2003\");if (vEYq3.getUTCFullYear().toString" ascii
    $s2 = "var vDJi5 = new Function(\"s\", '{var vEYq3 = new Date();vEYq3[\"setUTCFullYear\"](\"2003\");if (vEYq3.getUTCFullYear().toString" ascii
    $s3 = "function vRPa2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vSy6 = s.split(\"##\"); return vSy6.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}