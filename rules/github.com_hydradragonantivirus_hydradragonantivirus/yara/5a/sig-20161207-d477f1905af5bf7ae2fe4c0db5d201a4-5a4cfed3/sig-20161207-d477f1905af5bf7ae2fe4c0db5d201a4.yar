rule sig_20161207_d477f1905af5bf7ae2fe4c0db5d201a4 {
  meta:
    description = "datamaliciousorder - file 20161207_d477f1905af5bf7ae2fe4c0db5d201a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0d97333b26e6ee2a22727a5b5d3e7d67747e474aa0117fa4859ddd8ee55c16b"

  strings:
    $s1 = "var vPIl0 = new Function(\"vOj8\", '{return vOj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNk7 = new Function(\"vOj8" ascii
    $s2 = " new Date();vNKf5[\"setUTCFullYear\"](\"2003\");if (vNKf5.getUTCFullYear().toString(10) == \"2003\") {var vFVd9 = vOj8.split(\"#" ascii
    $s3 = "var vPIl0 = new Function(\"vOj8\", '{return vOj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNk7 = new Function(\"vOj8" ascii
    $s4 = "return vFVd9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}