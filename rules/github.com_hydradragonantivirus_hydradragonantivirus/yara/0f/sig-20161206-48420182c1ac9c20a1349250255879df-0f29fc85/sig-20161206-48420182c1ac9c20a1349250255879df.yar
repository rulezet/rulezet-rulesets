rule sig_20161206_48420182c1ac9c20a1349250255879df {
  meta:
    description = "datamaliciousorder - file 20161206_48420182c1ac9c20a1349250255879df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c6a6a58f6721e835cceaba290495412b86cd048048822d4c8162fdadc6ff8a"

  strings:
    $s1 = "var vSv8 = new Function(\"s\", '{var vFy0 = new Date();vFy0[\"setUTCFullYear\"](\"2003\");if (vFy0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vSv8 = new Function(\"s\", '{var vFy0 = new Date();vFy0[\"setUTCFullYear\"](\"2003\");if (vFy0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vQPg9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vGAl2 = s.split(\"##\"); return vGAl2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}