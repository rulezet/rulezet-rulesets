rule sig_20161207_9dcf34cbd4c6db963127c90b34268268 {
  meta:
    description = "datamaliciousorder - file 20161207_9dcf34cbd4c6db963127c90b34268268.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32c0201f46d251cd0dc5f073233641a3584a69277260f51c1a3062b57db9ac6b"

  strings:
    $s1 = "var vLJc2 = new Function(\"vTk6\", '{return vTk6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDLk2 = new Function(\"vTk6" ascii
    $s2 = "= new Date();vCIx5[\"setUTCFullYear\"](\"2003\");if (vCIx5.getUTCFullYear().toString(10) == \"2003\") {var vFDj6 = vTk6.split(\"" ascii
    $s3 = "var vLJc2 = new Function(\"vTk6\", '{return vTk6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDLk2 = new Function(\"vTk6" ascii
    $s4 = " return vFDj6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}