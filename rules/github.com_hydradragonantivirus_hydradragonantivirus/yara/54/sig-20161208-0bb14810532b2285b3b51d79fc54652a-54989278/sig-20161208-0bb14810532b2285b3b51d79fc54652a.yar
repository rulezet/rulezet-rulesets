rule sig_20161208_0bb14810532b2285b3b51d79fc54652a {
  meta:
    description = "datamaliciousorder - file 20161208_0bb14810532b2285b3b51d79fc54652a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00ef6bc8daf31ec15b2cafe0febdc3fae1b0786acf17288b49ae2e2fc0ddd92e"

  strings:
    $s1 = "var vUb6 = new Function(\"vOu1\", '{return vOu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFz5 = new Function(\"vOu1\"" ascii
    $s2 = "ew Date();vJv9[\"setUTC\"+\"FullYear\"](\"2003\");if (vJv9.getUTCFullYear().toString(10) == \"2003\") {var vXIv7 = vOu1.split(\"" ascii
    $s3 = "eturn vXIv7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUb6 = new Function(\"vOu1\", '{return vOu1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFz5 = new Function(\"vOu1\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}