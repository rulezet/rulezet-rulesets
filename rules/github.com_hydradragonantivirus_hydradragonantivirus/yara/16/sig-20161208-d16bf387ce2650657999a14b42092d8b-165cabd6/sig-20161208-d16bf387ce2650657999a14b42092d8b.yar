rule sig_20161208_d16bf387ce2650657999a14b42092d8b {
  meta:
    description = "datamaliciousorder - file 20161208_d16bf387ce2650657999a14b42092d8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41830e987497ebd263988ff5708851cca228d23de5e7bbdcc50b9600787cb9d6"

  strings:
    $s1 = "d4 = new Date();vIAd4[\"setUTC\"+\"FullYear\"](\"2003\");if (vIAd4.getUTCFullYear().toString(10) == \"2003\") {var vYLx8 = vFFe1" ascii
    $s2 = "var vKQb3 = new Function(\"vFFe1\", '{return vFFe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNAr2 = new Function(\"vF" ascii
    $s3 = "var vKQb3 = new Function(\"vFFe1\", '{return vFFe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNAr2 = new Function(\"vF" ascii
    $s4 = "####\"); return vYLx8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}