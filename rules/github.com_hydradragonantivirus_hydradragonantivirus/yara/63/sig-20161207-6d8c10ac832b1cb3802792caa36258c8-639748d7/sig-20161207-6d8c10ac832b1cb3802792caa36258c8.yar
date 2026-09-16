rule sig_20161207_6d8c10ac832b1cb3802792caa36258c8 {
  meta:
    description = "datamaliciousorder - file 20161207_6d8c10ac832b1cb3802792caa36258c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17a26409c9e31dc1e12956eeac7d1d8a5282bd2be18cc2ba6fe1b610355f1f7d"

  strings:
    $s1 = "7 = new Date();vJa7[\"setUTCFullYear\"](\"2003\");if (vJa7.getUTCFullYear().toString(10) == \"2003\") {var vHj1 = vTJe1.split(\"" ascii
    $s2 = "var vQLi3 = new Function(\"vTJe1\", '{return vTJe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLJs0 = new Function(\"vT" ascii
    $s3 = "var vQLi3 = new Function(\"vTJe1\", '{return vTJe1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLJs0 = new Function(\"vT" ascii
    $s4 = " return vHj1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}