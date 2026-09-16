rule sig_20161208_02b3666012e645a1ecf84f4d87f3bc8d {
  meta:
    description = "datamaliciousorder - file 20161208_02b3666012e645a1ecf84f4d87f3bc8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d61972e232e8d8a9cbe8f4cc80999fc0515c621c5ffbea5017d6ce14a2708928"

  strings:
    $s1 = " = new Date();vDq7[\"setUTC\"+\"FullYear\"](\"2003\");if (vDq7.getUTCFullYear().toString(10) == \"2003\") {var vHh2 = vFXw2.spli" ascii
    $s2 = "var vEZy0 = new Function(\"vFXw2\", '{return vFXw2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQi9 = new Function(\"vFX" ascii
    $s3 = "var vEZy0 = new Function(\"vFXw2\", '{return vFXw2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQi9 = new Function(\"vFX" ascii
    $s4 = "); return vHh2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}