rule sig_20161208_17f102b9b64ee7e8bb2a489094d029f1 {
  meta:
    description = "datamaliciousorder - file 20161208_17f102b9b64ee7e8bb2a489094d029f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdde9c55170278e5e458b849d4a23df2364f4b580101c4ba8cd946919bcd32c4"

  strings:
    $s1 = "var vMUx9 = new Function(\"vPt3\", '{return vPt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGQw4 = new Function(\"vPt3" ascii
    $s2 = " new Date();vJl0[\"setUTC\"+\"FullYear\"](\"2003\");if (vJl0.getUTCFullYear().toString(10) == \"2003\") {var vAEs0 = vPt3.split(" ascii
    $s3 = " return vAEs0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMUx9 = new Function(\"vPt3\", '{return vPt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGQw4 = new Function(\"vPt3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}