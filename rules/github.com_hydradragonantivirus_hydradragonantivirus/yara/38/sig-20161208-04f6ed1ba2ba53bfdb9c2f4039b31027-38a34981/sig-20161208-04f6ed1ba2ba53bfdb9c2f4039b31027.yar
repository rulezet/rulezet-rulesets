rule sig_20161208_04f6ed1ba2ba53bfdb9c2f4039b31027 {
  meta:
    description = "datamaliciousorder - file 20161208_04f6ed1ba2ba53bfdb9c2f4039b31027.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "180930c2a4b0fe941d740708fe0546ae5fdb1ff719b8f030dac36513fb7e062a"

  strings:
    $s1 = "var vKd7 = new Function(\"vQp8\", '{return vQp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLo5 = new Function(\"vQp8\"" ascii
    $s2 = "ew Date();vZn2[\"setUTC\"+\"FullYear\"](\"2003\");if (vZn2.getUTCFullYear().toString(10) == \"2003\") {var vEUv8 = vQp8.split(\"" ascii
    $s3 = "var vKd7 = new Function(\"vQp8\", '{return vQp8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLo5 = new Function(\"vQp8\"" ascii
    $s4 = "eturn vEUv8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}