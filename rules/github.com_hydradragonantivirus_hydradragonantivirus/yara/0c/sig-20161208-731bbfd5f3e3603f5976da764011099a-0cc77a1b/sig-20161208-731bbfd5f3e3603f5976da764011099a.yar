rule sig_20161208_731bbfd5f3e3603f5976da764011099a {
  meta:
    description = "datamaliciousorder - file 20161208_731bbfd5f3e3603f5976da764011099a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d492ca29c480aef2456def84d78df92a06e14382b405acf7e8959787752fc49c"

  strings:
    $s1 = " = new Date();vZc4[\"setUTC\"+\"FullYear\"](\"2003\");if (vZc4.getUTCFullYear().toString(10) == \"2003\") {var vIo7 = vKUt3.spli" ascii
    $s2 = "var vZGi6 = new Function(\"vKUt3\", '{return vKUt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDa5 = new Function(\"vKU" ascii
    $s3 = "var vZGi6 = new Function(\"vKUt3\", '{return vKUt3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDa5 = new Function(\"vKU" ascii
    $s4 = "); return vIo7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}