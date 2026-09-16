rule sig_20161207_87000b4b2aa78d43d693ea37e253c04e {
  meta:
    description = "datamaliciousorder - file 20161207_87000b4b2aa78d43d693ea37e253c04e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20a074c0a8aa0a2a464d453945c6661c7b5550159c684d8f555fd58ea6d00428"

  strings:
    $s1 = "var vLIr0 = new Function(\"vCNf2\", '{var vUv1 = new Date();vUv1[\"setUTCFullYear\"](\"2003\");if (vUv1.getUTCFullYear().toStrin" ascii
    $s2 = "var vLIr0 = new Function(\"vCNf2\", '{var vUv1 = new Date();vUv1[\"setUTCFullYear\"](\"2003\");if (vUv1.getUTCFullYear().toStrin" ascii
    $s3 = "var vHDs4 = new Function(\"vCNf2\", '{return vCNf2.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vYw0 = vCNf2.split(\"###\"); return vYw0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}