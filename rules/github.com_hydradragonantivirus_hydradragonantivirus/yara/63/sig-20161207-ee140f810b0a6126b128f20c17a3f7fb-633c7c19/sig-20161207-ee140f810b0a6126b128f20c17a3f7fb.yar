rule sig_20161207_ee140f810b0a6126b128f20c17a3f7fb {
  meta:
    description = "datamaliciousorder - file 20161207_ee140f810b0a6126b128f20c17a3f7fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eb198e7226cd8540885fb98821f9afd3bccf2ff91d78fe03e6bcdaa8945433e"

  strings:
    $s1 = "var vXFl3 = new Function(\"vMm5\", '{return vMm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDm4 = new Function(\"vMm5" ascii
    $s2 = " new Date();vEQq8[\"setUTCFullYear\"](\"2003\");if (vEQq8.getUTCFullYear().toString(10) == \"2003\") {var vWQj2 = vMm5.split(\"#" ascii
    $s3 = "return vWQj2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vXFl3 = new Function(\"vMm5\", '{return vMm5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDm4 = new Function(\"vMm5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}