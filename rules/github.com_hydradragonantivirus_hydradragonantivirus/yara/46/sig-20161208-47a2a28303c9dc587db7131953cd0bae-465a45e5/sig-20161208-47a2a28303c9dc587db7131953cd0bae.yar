rule sig_20161208_47a2a28303c9dc587db7131953cd0bae {
  meta:
    description = "datamaliciousorder - file 20161208_47a2a28303c9dc587db7131953cd0bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f94f3b6d20c61bde42dbf149426018fa55b7c65bf94219b79f5e0452df64c3c"

  strings:
    $s1 = "new Date();vHDd8[\"setUTC\"+\"FullYear\"](\"2003\");if (vHDd8.getUTCFullYear().toString(10) == \"2003\") {var vUFk6 = vXr9.split" ascii
    $s2 = "var vYj8 = new Function(\"vXr9\", '{return vXr9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWa3 = new Function(\"vXr9\"" ascii
    $s3 = "var vYj8 = new Function(\"vXr9\", '{return vXr9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWa3 = new Function(\"vXr9\"" ascii
    $s4 = "; return vUFk6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}