rule sig_20161208_eb7783a44d4cb1db9823b4c04a56329f {
  meta:
    description = "datamaliciousorder - file 20161208_eb7783a44d4cb1db9823b4c04a56329f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72cdc619982d3be45e7c90c01e0a7193e38ab76d2b64a2b5dceba28a3f303d02"

  strings:
    $s1 = "var vHm1 = new Function(\"vZv0\", '{return vZv0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCq4 = new Function(\"vZv0\"" ascii
    $s2 = "ew Date();vFc7[\"setUTC\"+\"FullYear\"](\"2003\");if (vFc7.getUTCFullYear().toString(10) == \"2003\") {var vZh2 = vZv0.split(\"#" ascii
    $s3 = "var vHm1 = new Function(\"vZv0\", '{return vZv0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCq4 = new Function(\"vZv0\"" ascii
    $s4 = "turn vZh2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}