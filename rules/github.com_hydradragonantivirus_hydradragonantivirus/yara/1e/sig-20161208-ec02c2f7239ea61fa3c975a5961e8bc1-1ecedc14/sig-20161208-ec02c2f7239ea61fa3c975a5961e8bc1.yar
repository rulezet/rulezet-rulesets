rule sig_20161208_ec02c2f7239ea61fa3c975a5961e8bc1 {
  meta:
    description = "datamaliciousorder - file 20161208_ec02c2f7239ea61fa3c975a5961e8bc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48744d83c187eaa110cc191cb3d49af7234b49dfd061bcf287fc01b6b83b4358"

  strings:
    $s1 = "new Date();vMHc9[\"setUTC\"+\"FullYear\"](\"2003\");if (vMHc9.getUTCFullYear().toString(10) == \"2003\") {var vSLo7 = vQn1.split" ascii
    $s2 = "var vSf7 = new Function(\"vQn1\", '{return vQn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr4 = new Function(\"vQn1\"" ascii
    $s3 = "var vSf7 = new Function(\"vQn1\", '{return vQn1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vMr4 = new Function(\"vQn1\"" ascii
    $s4 = "; return vSLo7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}