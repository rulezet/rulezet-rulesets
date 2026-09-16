rule sig_20161207_ae9d38898e5655d9cdf3da50830ac9ec {
  meta:
    description = "datamaliciousorder - file 20161207_ae9d38898e5655d9cdf3da50830ac9ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc29aa582acd1de4e7e554a02f7a7a4e506a942b647b0302ac9fa9f19c8d63c8"

  strings:
    $s1 = " new Date();vWh1[\"setUTCFullYear\"](\"2003\");if (vWh1.getUTCFullYear().toString(10) == \"2003\") {var vOc9 = vCz8.split(\"####" ascii
    $s2 = "var vWDp7 = new Function(\"vCz8\", '{return vCz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYFs1 = new Function(\"vCz8" ascii
    $s3 = "urn vOc9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vWDp7 = new Function(\"vCz8\", '{return vCz8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYFs1 = new Function(\"vCz8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}