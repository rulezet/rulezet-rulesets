rule sig_20161206_31e5424050416d95a27c51a30fb36ea7 {
  meta:
    description = "datamaliciousorder - file 20161206_31e5424050416d95a27c51a30fb36ea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac7d07dc3d39d6f2304c584a669697f023ff47d958f60b0376809b5c8c490038"

  strings:
    $s1 = "var vOLx1 = new Function(\"s\", '{var vNQd1 = new Date();vNQd1[\"setUTCFullYear\"](\"2003\");if (vNQd1.getUTCFullYear().toString" ascii
    $s2 = "var vOLx1 = new Function(\"s\", '{var vNQd1 = new Date();vNQd1[\"setUTCFullYear\"](\"2003\");if (vNQd1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vKCs1 = s.split(\"##\"); return vKCs1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vEw6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}