rule sig_20161208_c3a383856334b7917ca4ceabea6d769c {
  meta:
    description = "datamaliciousorder - file 20161208_c3a383856334b7917ca4ceabea6d769c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0170e9e18e8f372300870dd3f2206ce0991dccb5f9195470658c50246e4d2605"

  strings:
    $s1 = "ew Date();vXi2[\"setUTC\"+\"FullYear\"](\"2003\");if (vXi2.getUTCFullYear().toString(10) == \"2003\") {var vNs9 = vRt0.split(\"#" ascii
    $s2 = "var vBm5 = new Function(\"vRt0\", '{return vRt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDg1 = new Function(\"vRt0\"" ascii
    $s3 = "turn vNs9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vBm5 = new Function(\"vRt0\", '{return vRt0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDg1 = new Function(\"vRt0\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}