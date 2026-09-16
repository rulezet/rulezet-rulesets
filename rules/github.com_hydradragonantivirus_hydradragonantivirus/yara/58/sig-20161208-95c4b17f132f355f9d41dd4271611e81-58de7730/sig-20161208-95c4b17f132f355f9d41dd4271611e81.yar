rule sig_20161208_95c4b17f132f355f9d41dd4271611e81 {
  meta:
    description = "datamaliciousorder - file 20161208_95c4b17f132f355f9d41dd4271611e81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e8780071b94161dec99577584a3f7c85a93a26f348a67a3eafc236984f0b7d"

  strings:
    $s1 = "new Date();vVq1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVq1.getUTCFullYear().toString(10) == \"2003\") {var vYz1 = vJf9.split(\"" ascii
    $s2 = "var vUQw0 = new Function(\"vJf9\", '{return vJf9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLl0 = new Function(\"vJf9" ascii
    $s3 = "eturn vYz1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUQw0 = new Function(\"vJf9\", '{return vJf9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLl0 = new Function(\"vJf9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}