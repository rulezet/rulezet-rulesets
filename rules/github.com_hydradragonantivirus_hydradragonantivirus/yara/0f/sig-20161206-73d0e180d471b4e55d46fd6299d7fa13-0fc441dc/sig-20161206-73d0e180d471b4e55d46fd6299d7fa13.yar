rule sig_20161206_73d0e180d471b4e55d46fd6299d7fa13 {
  meta:
    description = "datamaliciousorder - file 20161206_73d0e180d471b4e55d46fd6299d7fa13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32eecb7d5f10cc35b2d2027025a9ca7cff674e58ff0f2b782356689e320cbc98"

  strings:
    $s1 = "var vXIc1 = new Function(\"s\", '{var vYi3 = new Date();vYi3[\"setUTCFullYear\"](\"2003\");if (vYi3.getUTCFullYear().toString(10" ascii
    $s2 = "var vXIc1 = new Function(\"s\", '{var vYi3 = new Date();vYi3[\"setUTCFullYear\"](\"2003\");if (vYi3.getUTCFullYear().toString(10" ascii
    $s3 = "function vTz5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vAi7 = s.split(\"##\"); return vAi7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}