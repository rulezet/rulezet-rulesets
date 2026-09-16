rule sig_20161207_8671369c20f7456d70c82189d5dd5b16 {
  meta:
    description = "datamaliciousorder - file 20161207_8671369c20f7456d70c82189d5dd5b16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ec20a812573b77afd44fe99372c4f7a553617dd8a163c7de83185dd4e285a7d"

  strings:
    $s1 = "var vRh8 = new Function(\"vRLz4\", '{var vDVs5 = new Date();vDVs5[\"setUTCFullYear\"](\"2003\");if (vDVs5.getUTCFullYear().toStr" ascii
    $s2 = "var vRh8 = new Function(\"vRLz4\", '{var vDVs5 = new Date();vDVs5[\"setUTCFullYear\"](\"2003\");if (vDVs5.getUTCFullYear().toStr" ascii
    $s3 = "var vFDb0 = new Function(\"vRLz4\", '{return vRLz4.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vOf0 = vRLz4.split(\"###\"); return vOf0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}