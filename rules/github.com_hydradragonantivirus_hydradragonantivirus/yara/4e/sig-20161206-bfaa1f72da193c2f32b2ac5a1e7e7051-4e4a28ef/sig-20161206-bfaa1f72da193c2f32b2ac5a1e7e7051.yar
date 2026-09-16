rule sig_20161206_bfaa1f72da193c2f32b2ac5a1e7e7051 {
  meta:
    description = "datamaliciousorder - file 20161206_bfaa1f72da193c2f32b2ac5a1e7e7051.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27c5349140e029cb7044020a106c2b79d1210622b9eb52275c8fc39cce7980e4"

  strings:
    $s1 = "var vRKy8 = new Function(\"s\", '{var vKh5 = new Date();vKh5[\"setUTCFullYear\"](\"2003\");if (vKh5.getUTCFullYear().toString(10" ascii
    $s2 = "var vRKy8 = new Function(\"s\", '{var vKh5 = new Date();vKh5[\"setUTCFullYear\"](\"2003\");if (vKh5.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vUDe4 = s.split(\"##\"); return vUDe4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vTg2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}