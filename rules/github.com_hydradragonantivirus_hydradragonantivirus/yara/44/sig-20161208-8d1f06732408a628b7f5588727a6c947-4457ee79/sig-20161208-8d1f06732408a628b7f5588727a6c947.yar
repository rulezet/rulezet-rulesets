rule sig_20161208_8d1f06732408a628b7f5588727a6c947 {
  meta:
    description = "datamaliciousorder - file 20161208_8d1f06732408a628b7f5588727a6c947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b3069e3b660203f51dd709f6598e1ac3dd5bea2a753a0f93b9e84e42f882971"

  strings:
    $s1 = "var vLJk5 = new Function(\"vYs6\", '{return vYs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNYs8 = new Function(\"vYs6" ascii
    $s2 = " new Date();vOl7[\"setUTC\"+\"FullYear\"](\"2003\");if (vOl7.getUTCFullYear().toString(10) == \"2003\") {var vZh9 = vYs6.split(" ascii
    $s3 = "var vLJk5 = new Function(\"vYs6\", '{return vYs6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNYs8 = new Function(\"vYs6" ascii
    $s4 = "return vZh9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}