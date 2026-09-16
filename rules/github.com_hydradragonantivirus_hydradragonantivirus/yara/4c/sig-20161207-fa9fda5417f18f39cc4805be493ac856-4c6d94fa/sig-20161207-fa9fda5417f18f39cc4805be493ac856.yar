rule sig_20161207_fa9fda5417f18f39cc4805be493ac856 {
  meta:
    description = "datamaliciousorder - file 20161207_fa9fda5417f18f39cc4805be493ac856.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6907c9affcccde39b3326a575365286c0392244b524be67cccab7c20e157289b"

  strings:
    $s1 = "var vJe9 = new Function(\"vSQu9\", '{var vVy7 = new Date();vVy7[\"setUTCFullYear\"](\"2003\");if (vVy7.getUTCFullYear().toString" ascii
    $s2 = "var vJe9 = new Function(\"vSQu9\", '{var vVy7 = new Date();vVy7[\"setUTCFullYear\"](\"2003\");if (vVy7.getUTCFullYear().toString" ascii
    $s3 = "var vGVc5 = new Function(\"vSQu9\", '{return vSQu9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vMNy8 = vSQu9.split(\"###\"); return vMNy8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}