rule sig_20161207_9bbae2a8bd867048bd5eaf4f05891acc {
  meta:
    description = "datamaliciousorder - file 20161207_9bbae2a8bd867048bd5eaf4f05891acc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d5e9d2dc6570eb81938a7afffd7c44a598f45aee1a56b70a26a54848e41e100"

  strings:
    $s1 = " new Date();vJd1[\"setUTCFullYear\"](\"2003\");if (vJd1.getUTCFullYear().toString(10) == \"2003\") {var vLTg8 = vAy6.split(\"###" ascii
    $s2 = "var vVJu8 = new Function(\"vAy6\", '{return vAy6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTAy9 = new Function(\"vAy6" ascii
    $s3 = "turn vLTg8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vVJu8 = new Function(\"vAy6\", '{return vAy6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vTAy9 = new Function(\"vAy6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}