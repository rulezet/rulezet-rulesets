rule sig_20161208_14d47e66985f164f861e67a26d6974be {
  meta:
    description = "datamaliciousorder - file 20161208_14d47e66985f164f861e67a26d6974be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "953a73b59ec3ca4c7247fccc9838b4731b0d93d4137ade4a5707fad1a9fbf560"

  strings:
    $s1 = "new Date();vCv5[\"setUTC\"+\"FullYear\"](\"2003\");if (vCv5.getUTCFullYear().toString(10) == \"2003\") {var vEw7 = vEu9.split(\"" ascii
    $s2 = "var vTEd6 = new Function(\"vEu9\", '{return vEu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYa6 = new Function(\"vEu9" ascii
    $s3 = "var vTEd6 = new Function(\"vEu9\", '{return vEu9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYa6 = new Function(\"vEu9" ascii
    $s4 = "eturn vEw7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}