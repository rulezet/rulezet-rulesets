rule sig_20161208_a6edb50f5d79fd711fb559d1188b4326 {
  meta:
    description = "datamaliciousorder - file 20161208_a6edb50f5d79fd711fb559d1188b4326.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a5cf9f4eb2faff446933eddd4d5457f3b9582b91fbc0d59f5ad1f0fd667cbbd"

  strings:
    $s1 = "var vAt1 = new Function(\"vSPp5\", '{return vSPp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHc1 = new Function(\"vSPp" ascii
    $s2 = " = new Date();vMJe7[\"setUTC\"+\"FullYear\"](\"2003\");if (vMJe7.getUTCFullYear().toString(10) == \"2003\") {var vLn0 = vSPp5.sp" ascii
    $s3 = "#\"); return vLn0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vAt1 = new Function(\"vSPp5\", '{return vSPp5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHc1 = new Function(\"vSPp" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}