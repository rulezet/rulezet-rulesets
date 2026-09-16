rule sig_20161208_930dcba2b5bd8907cc4dee4d48203f70 {
  meta:
    description = "datamaliciousorder - file 20161208_930dcba2b5bd8907cc4dee4d48203f70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af9e7e75f4b38c5b816a43cf02914d3b96fe4c5459ea0ea143f1f1de983fee8"

  strings:
    $s1 = "var vZk6 = new Function(\"vKLw6\", '{return vKLw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIAs3 = new Function(\"vKL" ascii
    $s2 = " = new Date();vJy6[\"setUTC\"+\"FullYear\"](\"2003\");if (vJy6.getUTCFullYear().toString(10) == \"2003\") {var vBa7 = vKLw6.spli" ascii
    $s3 = "var vZk6 = new Function(\"vKLw6\", '{return vKLw6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIAs3 = new Function(\"vKL" ascii
    $s4 = "); return vBa7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}