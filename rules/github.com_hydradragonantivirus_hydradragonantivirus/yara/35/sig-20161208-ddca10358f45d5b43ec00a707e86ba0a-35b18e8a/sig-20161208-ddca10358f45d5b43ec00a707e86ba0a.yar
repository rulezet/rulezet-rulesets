rule sig_20161208_ddca10358f45d5b43ec00a707e86ba0a {
  meta:
    description = "datamaliciousorder - file 20161208_ddca10358f45d5b43ec00a707e86ba0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1803bb72e19fbb5d6fb2f854a3b62b10c9e0b8ef666031d91db70880019ec17d"

  strings:
    $s1 = "new Date();vRy7[\"setUTC\"+\"FullYear\"](\"2003\");if (vRy7.getUTCFullYear().toString(10) == \"2003\") {var vVn9 = vYy0.split(\"" ascii
    $s2 = "var vCo7 = new Function(\"vYy0\", '{return vYy0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHDg0 = new Function(\"vYy0" ascii
    $s3 = "var vCo7 = new Function(\"vYy0\", '{return vYy0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHDg0 = new Function(\"vYy0" ascii
    $s4 = "eturn vVn9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}