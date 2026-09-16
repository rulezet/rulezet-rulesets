rule sig_20161207_4c5c32e36ad8b9aeb82555c61919c25e {
  meta:
    description = "datamaliciousorder - file 20161207_4c5c32e36ad8b9aeb82555c61919c25e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63dd4f55ec836548060b75c7a9e273b4ee59fb71dc6ad5bac55fa3fa52ab91ca"

  strings:
    $s1 = "var vTFt6 = new Function(\"vBo3\", '{var vWn7 = new Date();vWn7[\"setUTCFullYear\"](\"2003\");if (vWn7.getUTCFullYear().toString" ascii
    $s2 = "var vTFt6 = new Function(\"vBo3\", '{var vWn7 = new Date();vWn7[\"setUTCFullYear\"](\"2003\");if (vWn7.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vPn0 = vBo3.split(\"###\"); return vPn0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vHIr5 = new Function(\"vBo3\", '{return vBo3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}