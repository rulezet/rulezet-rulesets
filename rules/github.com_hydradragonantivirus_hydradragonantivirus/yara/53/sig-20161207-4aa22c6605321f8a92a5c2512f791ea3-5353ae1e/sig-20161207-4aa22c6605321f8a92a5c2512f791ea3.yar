rule sig_20161207_4aa22c6605321f8a92a5c2512f791ea3 {
  meta:
    description = "datamaliciousorder - file 20161207_4aa22c6605321f8a92a5c2512f791ea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "103f37eac8a2ddfab54da6431b5a658c14f7cb698fbd1b55210466cacf8145b9"

  strings:
    $s1 = "var vNi2 = new Function(\"vKa0\", '{return vKa0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZJu8 = new Function(\"vKa0" ascii
    $s2 = "new Date();vOc6[\"setUTCFullYear\"](\"2003\");if (vOc6.getUTCFullYear().toString(10) == \"2003\") {var vPa7 = vKa0.split(\"####" ascii
    $s3 = "rn vPa7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNi2 = new Function(\"vKa0\", '{return vKa0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZJu8 = new Function(\"vKa0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}