rule sig_20161207_929c0d91420beed4cb3c651a9ee067ff {
  meta:
    description = "datamaliciousorder - file 20161207_929c0d91420beed4cb3c651a9ee067ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9e3f91ab24941e9b3a366c3801b03c1b392f071086c1db4c3425d14d0fd656a"

  strings:
    $s1 = "var vOq5 = new Function(\"vVTx3\", '{return vVTx3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUKb4 = new Function(\"vVT" ascii
    $s2 = "9 = new Date();vETf9[\"setUTCFullYear\"](\"2003\");if (vETf9.getUTCFullYear().toString(10) == \"2003\") {var vKNi4 = vVTx3.split" ascii
    $s3 = "var vOq5 = new Function(\"vVTx3\", '{return vVTx3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUKb4 = new Function(\"vVT" ascii
    $s4 = "\"); return vKNi4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}