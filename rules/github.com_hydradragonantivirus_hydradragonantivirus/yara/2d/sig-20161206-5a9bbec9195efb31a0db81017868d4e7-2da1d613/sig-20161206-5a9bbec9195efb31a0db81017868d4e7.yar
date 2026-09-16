rule sig_20161206_5a9bbec9195efb31a0db81017868d4e7 {
  meta:
    description = "datamaliciousorder - file 20161206_5a9bbec9195efb31a0db81017868d4e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cae8b0114ada2a8f611958acec49243107ea0fdcc296894c66fa48392bb8258"

  strings:
    $s1 = "var vRk0 = new Function(\"s\", '{var vQLx0 = new Date();vQLx0[\"setUTCFullYear\"](\"2003\");if (vQLx0.getUTCFullYear().toString(" ascii
    $s2 = "var vRk0 = new Function(\"s\", '{var vQLx0 = new Date();vQLx0[\"setUTCFullYear\"](\"2003\");if (vQLx0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vIx8 = s.split(\"##\"); return vIx8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vYEf3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}