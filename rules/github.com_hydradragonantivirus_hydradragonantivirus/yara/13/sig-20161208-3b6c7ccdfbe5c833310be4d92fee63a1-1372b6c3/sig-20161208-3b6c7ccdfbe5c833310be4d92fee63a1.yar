rule sig_20161208_3b6c7ccdfbe5c833310be4d92fee63a1 {
  meta:
    description = "datamaliciousorder - file 20161208_3b6c7ccdfbe5c833310be4d92fee63a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c998f68c519635e91d6f349f09bce28407026e231944613cbee029d82747cca"

  strings:
    $s1 = "var vWb5 = new Function(\"vKu5\", '{return vKu5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFm0 = new Function(\"vKu5\"" ascii
    $s2 = "new Date();vKCb0[\"setUTC\"+\"FullYear\"](\"2003\");if (vKCb0.getUTCFullYear().toString(10) == \"2003\") {var vDp2 = vKu5.split(" ascii
    $s3 = "var vWb5 = new Function(\"vKu5\", '{return vKu5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFm0 = new Function(\"vKu5\"" ascii
    $s4 = " return vDp2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}