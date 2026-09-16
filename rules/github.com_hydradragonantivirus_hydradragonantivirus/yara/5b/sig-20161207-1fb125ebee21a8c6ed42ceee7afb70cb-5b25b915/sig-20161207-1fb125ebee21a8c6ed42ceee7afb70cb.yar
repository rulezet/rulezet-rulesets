rule sig_20161207_1fb125ebee21a8c6ed42ceee7afb70cb {
  meta:
    description = "datamaliciousorder - file 20161207_1fb125ebee21a8c6ed42ceee7afb70cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1af416a2630bd6368b90c5fe5fe9081af0c44e475c8919a509cec53570fcd020"

  strings:
    $s1 = "var vRXe0 = new Function(\"vYl7\", '{return vYl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNz8 = new Function(\"vYl7" ascii
    $s2 = " new Date();vCQv5[\"setUTCFullYear\"](\"2003\");if (vCQv5.getUTCFullYear().toString(10) == \"2003\") {var vLo6 = vYl7.split(\"##" ascii
    $s3 = "var vRXe0 = new Function(\"vYl7\", '{return vYl7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNz8 = new Function(\"vYl7" ascii
    $s4 = "eturn vLo6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}