rule sig_20161208_2620bd54c38aa7eec1585498814ac623 {
  meta:
    description = "datamaliciousorder - file 20161208_2620bd54c38aa7eec1585498814ac623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e180b40e06b83a6307ffa81f895edc740152590a7e3d667c246872dbba6b9c7"

  strings:
    $s1 = "var vGFs2 = new Function(\"vYYl2\", '{return vYYl2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEZt8 = new Function(\"vY" ascii
    $s2 = "p4 = new Date();vUQp4[\"setUTC\"+\"FullYear\"](\"2003\");if (vUQp4.getUTCFullYear().toString(10) == \"2003\") {var vZd5 = vYYl2." ascii
    $s3 = "var vGFs2 = new Function(\"vYYl2\", '{return vYYl2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEZt8 = new Function(\"vY" ascii
    $s4 = "###\"); return vZd5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}