rule sig_20161206_22e1698302c92692754b5890f7f6e133 {
  meta:
    description = "datamaliciousorder - file 20161206_22e1698302c92692754b5890f7f6e133.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a4fe989db292a8dab6cf131f97952d9b139ba386136c412f3b0c24c52c27118"

  strings:
    $s1 = "var vWx9 = new Function(\"s\", '{var vEZg0 = new Date();vEZg0[\"setUTCFullYear\"](\"2003\");if (vEZg0.getUTCFullYear().toString(" ascii
    $s2 = "var vWx9 = new Function(\"s\", '{var vEZg0 = new Date();vEZg0[\"setUTCFullYear\"](\"2003\");if (vEZg0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vEk3 = s.split(\"##\"); return vEk3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vOLp0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}