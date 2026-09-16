rule sig_20161206_de89c672a67bc99ba597546f7aed0ee6 {
  meta:
    description = "datamaliciousorder - file 20161206_de89c672a67bc99ba597546f7aed0ee6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "684e6b5a591f2616a54d58911792488f62e1498f07dab06b6f84c1c846217799"

  strings:
    $s1 = "var vVCg2 = new Function(\"s\", '{var vQBv7 = new Date();vQBv7[\"setUTCFullYear\"](\"2003\");if (vQBv7.getUTCFullYear().toString" ascii
    $s2 = "var vVCg2 = new Function(\"s\", '{var vQBv7 = new Date();vQBv7[\"setUTCFullYear\"](\"2003\");if (vQBv7.getUTCFullYear().toString" ascii
    $s3 = "function vBNi9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vAJy2 = s.split(\"##\"); return vAJy2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}