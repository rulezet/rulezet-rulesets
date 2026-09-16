rule sig_20161207_f5ea6bb02f9e2b9d17e92864cd01da05 {
  meta:
    description = "datamaliciousorder - file 20161207_f5ea6bb02f9e2b9d17e92864cd01da05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fd1e6401bb945404e9e30c9c562de97060d2ca03e9113b3a6c543b2cdfcbc12"

  strings:
    $s1 = " new Date();vHRj5[\"setUTCFullYear\"](\"2003\");if (vHRj5.getUTCFullYear().toString(10) == \"2003\") {var vDb5 = vUg6.split(\"##" ascii
    $s2 = "var vKKu0 = new Function(\"vUg6\", '{return vUg6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUk7 = new Function(\"vUg6" ascii
    $s3 = "eturn vDb5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vKKu0 = new Function(\"vUg6\", '{return vUg6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUk7 = new Function(\"vUg6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}