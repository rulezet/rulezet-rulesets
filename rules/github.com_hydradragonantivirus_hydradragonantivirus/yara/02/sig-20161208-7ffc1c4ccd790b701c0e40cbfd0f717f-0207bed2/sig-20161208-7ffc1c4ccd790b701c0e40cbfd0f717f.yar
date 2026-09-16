rule sig_20161208_7ffc1c4ccd790b701c0e40cbfd0f717f {
  meta:
    description = "datamaliciousorder - file 20161208_7ffc1c4ccd790b701c0e40cbfd0f717f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66dff65a1848ac23ccc7cdb205ea42048ec1f40b0a9d0bd1cf52306b72e8b1e9"

  strings:
    $s1 = "var vMJf3 = new Function(\"vUZx2\", '{return vUZx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDAt5 = new Function(\"vU" ascii
    $s2 = "o6 = new Date();vWBo6[\"setUTC\"+\"FullYear\"](\"2003\");if (vWBo6.getUTCFullYear().toString(10) == \"2003\") {var vQp3 = vUZx2." ascii
    $s3 = "###\"); return vQp3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMJf3 = new Function(\"vUZx2\", '{return vUZx2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDAt5 = new Function(\"vU" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}