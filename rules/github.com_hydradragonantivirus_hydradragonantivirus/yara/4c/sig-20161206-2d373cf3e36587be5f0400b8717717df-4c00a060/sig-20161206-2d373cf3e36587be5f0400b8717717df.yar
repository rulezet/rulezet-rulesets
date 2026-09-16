rule sig_20161206_2d373cf3e36587be5f0400b8717717df {
  meta:
    description = "datamaliciousorder - file 20161206_2d373cf3e36587be5f0400b8717717df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab84eee004a1d55bc079fd4c6283ef89de6ff49101b6bdb39e9f7cc3ddb73e5"

  strings:
    $s1 = "var vYs0 = new Function(\"s\", '{var vJx1 = new Date();vJx1[\"setUTCFullYear\"](\"2003\");if (vJx1.getUTCFullYear().toString(10)" ascii
    $s2 = "var vYs0 = new Function(\"s\", '{var vJx1 = new Date();vJx1[\"setUTCFullYear\"](\"2003\");if (vJx1.getUTCFullYear().toString(10)" ascii
    $s3 = "function vUb8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vHq7 = s.split(\"##\"); return vHq7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}