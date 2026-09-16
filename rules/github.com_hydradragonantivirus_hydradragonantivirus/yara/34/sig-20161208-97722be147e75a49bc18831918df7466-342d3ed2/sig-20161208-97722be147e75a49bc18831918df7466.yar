rule sig_20161208_97722be147e75a49bc18831918df7466 {
  meta:
    description = "datamaliciousorder - file 20161208_97722be147e75a49bc18831918df7466.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfa5d09ed4f84c6e92ec66eeac256115fe3a553ac273eb907f4c7d44218b87bd"

  strings:
    $s1 = "1 = new Date();vBYc1[\"setUTC\"+\"FullYear\"](\"2003\");if (vBYc1.getUTCFullYear().toString(10) == \"2003\") {var vPDw1 = vEZk8." ascii
    $s2 = "var vEPl2 = new Function(\"vEZk8\", '{return vEZk8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPd3 = new Function(\"vEZ" ascii
    $s3 = "###\"); return vPDw1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vEPl2 = new Function(\"vEZk8\", '{return vEZk8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPd3 = new Function(\"vEZ" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}