rule sig_20161206_148483b69fb06a6dfb4ca57714566931 {
  meta:
    description = "datamaliciousorder - file 20161206_148483b69fb06a6dfb4ca57714566931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d216e4d753b583054f57099d968495a4596c3e14cd57591eae9fe7b20899a3d9"

  strings:
    $s1 = "var vUIt7 = new Function(\"s\", '{var vROu8 = new Date();vROu8[\"setUTCFullYear\"](\"2003\");if (vROu8.getUTCFullYear().toString" ascii
    $s2 = "var vUIt7 = new Function(\"s\", '{var vROu8 = new Date();vROu8[\"setUTCFullYear\"](\"2003\");if (vROu8.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vJXe5 = s.split(\"##\"); return vJXe5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vUWn3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}