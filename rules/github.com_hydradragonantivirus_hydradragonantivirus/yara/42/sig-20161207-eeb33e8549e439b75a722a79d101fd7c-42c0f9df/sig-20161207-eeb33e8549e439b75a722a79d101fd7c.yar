rule sig_20161207_eeb33e8549e439b75a722a79d101fd7c {
  meta:
    description = "datamaliciousorder - file 20161207_eeb33e8549e439b75a722a79d101fd7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3ce66d90dbf1219d30043b5231a69cc3bbdcc0785783ca240c38cb2946a3847"

  strings:
    $s1 = "var vDDa7 = new Function(\"vZr7\", '{var vUh0 = new Date();vUh0[\"setUTCFullYear\"](\"2003\");if (vUh0.getUTCFullYear().toString" ascii
    $s2 = "var vDDa7 = new Function(\"vZr7\", '{var vUh0 = new Date();vUh0[\"setUTCFullYear\"](\"2003\");if (vUh0.getUTCFullYear().toString" ascii
    $s3 = "var vIb3 = new Function(\"vZr7\", '{return vZr7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vLj0 = vZr7.split(\"###\"); return vLj0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}