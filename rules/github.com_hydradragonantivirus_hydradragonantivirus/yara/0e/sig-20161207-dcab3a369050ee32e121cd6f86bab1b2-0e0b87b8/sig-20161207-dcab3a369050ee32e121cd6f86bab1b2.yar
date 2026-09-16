rule sig_20161207_dcab3a369050ee32e121cd6f86bab1b2 {
  meta:
    description = "datamaliciousorder - file 20161207_dcab3a369050ee32e121cd6f86bab1b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5c8e552f121c946d4c0296831c5c8b837aed50cad5e550a71dfddd5cc5782e"

  strings:
    $s1 = "var vZy3 = new Function(\"vJSa1\", '{return vJSa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAw3 = new Function(\"vJSa" ascii
    $s2 = " = new Date();vRGt8[\"setUTCFullYear\"](\"2003\");if (vRGt8.getUTCFullYear().toString(10) == \"2003\") {var vDe8 = vJSa1.split(" ascii
    $s3 = "var vZy3 = new Function(\"vJSa1\", '{return vJSa1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAw3 = new Function(\"vJSa" ascii
    $s4 = "; return vDe8.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}