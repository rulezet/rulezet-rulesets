rule sig_20161207_6790dcf64b4b362ca8be376f15db3d99 {
  meta:
    description = "datamaliciousorder - file 20161207_6790dcf64b4b362ca8be376f15db3d99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dabd27dcf3e5a3ef3c2b89c480a1c69c10bb1f9b2b53614c5e5d45026a175f64"

  strings:
    $s1 = "var vMJi0 = new Function(\"vCKl1\", '{var vEk0 = new Date();vEk0[\"setUTCFullYear\"](\"2003\");if (vEk0.getUTCFullYear().toStrin" ascii
    $s2 = "var vMJi0 = new Function(\"vCKl1\", '{var vEk0 = new Date();vEk0[\"setUTCFullYear\"](\"2003\");if (vEk0.getUTCFullYear().toStrin" ascii
    $s3 = "var vEg7 = new Function(\"vCKl1\", '{return vCKl1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vFc0 = vCKl1.split(\"###\"); return vFc0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}