rule sig_20161206_732a108dd6ce37c8902e8acca3efbd2c {
  meta:
    description = "datamaliciousorder - file 20161206_732a108dd6ce37c8902e8acca3efbd2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29df90a068ddd14b6cba8bf9fa23d5d165d03163b8d63f15fdb42f583a0a3902"

  strings:
    $s1 = "var vYt7 = new Function(\"s\", '{var vFXx4 = new Date();vFXx4[\"setUTCFullYear\"](\"2003\");if (vFXx4.getUTCFullYear().toString(" ascii
    $s2 = "var vYt7 = new Function(\"s\", '{var vFXx4 = new Date();vFXx4[\"setUTCFullYear\"](\"2003\");if (vFXx4.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vMm3 = s.split(\"##\"); return vMm3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vKMa1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}