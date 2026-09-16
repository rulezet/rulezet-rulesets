rule sig_20161206_029168feb9c205107ecf04dd7283db4a {
  meta:
    description = "datamaliciousorder - file 20161206_029168feb9c205107ecf04dd7283db4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1774350675a80227a55210fe917e0ade59ff71f830ee80e4beafa84b533c2f38"

  strings:
    $s1 = "var vTNt7 = new Function(\"s\", '{var vYh4 = new Date();vYh4[\"setUTCFullYear\"](\"2003\");if (vYh4.getUTCFullYear().toString(10" ascii
    $s2 = "var vTNt7 = new Function(\"s\", '{var vYh4 = new Date();vYh4[\"setUTCFullYear\"](\"2003\");if (vYh4.getUTCFullYear().toString(10" ascii
    $s3 = "function vPCi8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vMz5 = s.split(\"##\"); return vMz5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}