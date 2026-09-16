rule sig_20161206_a8012bc4045b144381b03173b1fda417 {
  meta:
    description = "datamaliciousorder - file 20161206_a8012bc4045b144381b03173b1fda417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40ef98bfad956dc3540b3013be8d067aef5cf141e9baf536ffe6264ce370a72c"

  strings:
    $s1 = "var vZNv8 = new Function(\"s\", '{var vOKs8 = new Date();vOKs8[\"setUTCFullYear\"](\"2003\");if (vOKs8.getUTCFullYear().toString" ascii
    $s2 = "var vZNv8 = new Function(\"s\", '{var vOKs8 = new Date();vOKs8[\"setUTCFullYear\"](\"2003\");if (vOKs8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vMs9 = s.split(\"##\"); return vMs9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQBa8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}