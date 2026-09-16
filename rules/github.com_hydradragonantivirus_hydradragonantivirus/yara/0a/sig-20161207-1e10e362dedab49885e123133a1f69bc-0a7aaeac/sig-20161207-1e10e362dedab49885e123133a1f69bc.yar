rule sig_20161207_1e10e362dedab49885e123133a1f69bc {
  meta:
    description = "datamaliciousorder - file 20161207_1e10e362dedab49885e123133a1f69bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f961e654be99ae24e3c64065fb92a1e6789c31f71630e98d1fd8b9bafc3731f"

  strings:
    $s1 = "var vSg8 = new Function(\"vUz0\", '{var vXi2 = new Date();vXi2[\"setUTCFullYear\"](\"2003\");if (vXi2.getUTCFullYear().toString(" ascii
    $s2 = "var vSg8 = new Function(\"vUz0\", '{var vXi2 = new Date();vXi2[\"setUTCFullYear\"](\"2003\");if (vXi2.getUTCFullYear().toString(" ascii
    $s3 = "var vUx6 = new Function(\"vUz0\", '{return vUz0.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vXVw3 = vUz0.split(\"###\"); return vXVw3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}