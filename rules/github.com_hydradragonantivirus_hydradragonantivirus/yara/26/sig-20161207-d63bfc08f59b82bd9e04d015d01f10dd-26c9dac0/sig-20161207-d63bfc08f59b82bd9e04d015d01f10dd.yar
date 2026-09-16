rule sig_20161207_d63bfc08f59b82bd9e04d015d01f10dd {
  meta:
    description = "datamaliciousorder - file 20161207_d63bfc08f59b82bd9e04d015d01f10dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6f724ace4f541e4655bdd65e2e39b05435bc0a6d576ed655d74feda260833d2"

  strings:
    $s1 = "var vJFt1 = new Function(\"vRj5\", '{var vPLq1 = new Date();vPLq1[\"setUTCFullYear\"](\"2003\");if (vPLq1.getUTCFullYear().toStr" ascii
    $s2 = "var vJFt1 = new Function(\"vRj5\", '{var vPLq1 = new Date();vPLq1[\"setUTCFullYear\"](\"2003\");if (vPLq1.getUTCFullYear().toStr" ascii
    $s3 = "var vJXs5 = new Function(\"vRj5\", '{return vRj5.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vLLk0 = vRj5.split(\"###\"); return vLLk0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}