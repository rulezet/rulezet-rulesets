rule sig_20161206_8f6ac2ad9a6b19360e740ebfe95efa84 {
  meta:
    description = "datamaliciousorder - file 20161206_8f6ac2ad9a6b19360e740ebfe95efa84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49d949036e2f20a8e4d0d76bcb9fce96fa6cca89e3200347d031ee1df2f01490"

  strings:
    $s1 = "var vGKa2 = new Function(\"s\", '{var vMQs3 = new Date();vMQs3[\"setUTCFullYear\"](\"2003\");if (vMQs3.getUTCFullYear().toString" ascii
    $s2 = "var vGKa2 = new Function(\"s\", '{var vMQs3 = new Date();vMQs3[\"setUTCFullYear\"](\"2003\");if (vMQs3.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vPw2 = s.split(\"##\"); return vPw2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSRc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}