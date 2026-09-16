rule sig_20161208_3e9397a805b91c2fc92bf013a53f33ac {
  meta:
    description = "datamaliciousorder - file 20161208_3e9397a805b91c2fc92bf013a53f33ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a07795fda5aea94b4e404f325743f9e30d7c8251684f73cf9ba0f1160d5be9f"

  strings:
    $s1 = "var vVo0 = new Function(\"vWt2\", '{return vWt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPZs5 = new Function(\"vWt2" ascii
    $s2 = "new Date();vXt8[\"setUTC\"+\"FullYear\"](\"2003\");if (vXt8.getUTCFullYear().toString(10) == \"2003\") {var vJi2 = vWt2.split(\"" ascii
    $s3 = "eturn vJi2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVo0 = new Function(\"vWt2\", '{return vWt2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPZs5 = new Function(\"vWt2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}