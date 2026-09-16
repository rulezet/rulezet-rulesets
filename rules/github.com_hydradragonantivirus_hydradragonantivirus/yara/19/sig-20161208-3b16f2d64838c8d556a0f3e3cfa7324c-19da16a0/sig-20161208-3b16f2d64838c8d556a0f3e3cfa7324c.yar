rule sig_20161208_3b16f2d64838c8d556a0f3e3cfa7324c {
  meta:
    description = "datamaliciousorder - file 20161208_3b16f2d64838c8d556a0f3e3cfa7324c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1234af152fcc2eb22cef99166c74a4ce0be46ab6d42b08dcc65a461c0782e3c"

  strings:
    $s1 = "var vNGt8 = new Function(\"vEBy5\", '{return vEBy5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZx4 = new Function(\"vEB" ascii
    $s2 = "6 = new Date();vPYr6[\"setUTC\"+\"FullYear\"](\"2003\");if (vPYr6.getUTCFullYear().toString(10) == \"2003\") {var vCt4 = vEBy5.s" ascii
    $s3 = "var vNGt8 = new Function(\"vEBy5\", '{return vEBy5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZx4 = new Function(\"vEB" ascii
    $s4 = "##\"); return vCt4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}