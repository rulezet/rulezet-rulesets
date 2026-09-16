rule sig_20161208_366da69f03026c2813f6124f193fc630 {
  meta:
    description = "datamaliciousorder - file 20161208_366da69f03026c2813f6124f193fc630.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a0b894f2ee595e901a293a03152079bbddcba377effdf73d03514e4e34d34d"

  strings:
    $s1 = "var vZVf7 = new Function(\"vOy1\", '{return vOy1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHJp9 = new Function(\"vOy1" ascii
    $s2 = "= new Date();vPAg9[\"setUTC\"+\"FullYear\"](\"2003\");if (vPAg9.getUTCFullYear().toString(10) == \"2003\") {var vQRb2 = vOy1.spl" ascii
    $s3 = "\"); return vQRb2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vZVf7 = new Function(\"vOy1\", '{return vOy1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHJp9 = new Function(\"vOy1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}