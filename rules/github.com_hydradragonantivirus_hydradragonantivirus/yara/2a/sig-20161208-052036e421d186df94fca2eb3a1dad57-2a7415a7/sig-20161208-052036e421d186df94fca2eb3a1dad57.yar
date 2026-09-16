rule sig_20161208_052036e421d186df94fca2eb3a1dad57 {
  meta:
    description = "datamaliciousorder - file 20161208_052036e421d186df94fca2eb3a1dad57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d22494548442e571fd5ecd6c12ecbc948b3084914a5139f655d8acc8a6a0ad75"

  strings:
    $s1 = "new Date();vFh0[\"setUTC\"+\"FullYear\"](\"2003\");if (vFh0.getUTCFullYear().toString(10) == \"2003\") {var vLKv2 = vNz3.split(" ascii
    $s2 = "var vCo2 = new Function(\"vNz3\", '{return vNz3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOCn9 = new Function(\"vNz3" ascii
    $s3 = "return vLKv2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCo2 = new Function(\"vNz3\", '{return vNz3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOCn9 = new Function(\"vNz3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}