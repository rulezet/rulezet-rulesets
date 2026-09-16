rule sig_20161207_3070e92a50465e7da578a4a6ef7ddcdd {
  meta:
    description = "datamaliciousorder - file 20161207_3070e92a50465e7da578a4a6ef7ddcdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1be928b987569a85e57f8f6591f0576143db1f00c9caa303008fb8790fe4543"

  strings:
    $s1 = "var vGPq4 = new Function(\"vDTg1\", '{var vLj3 = new Date();vLj3[\"setUTCFullYear\"](\"2003\");if (vLj3.getUTCFullYear().toStrin" ascii
    $s2 = "var vGPq4 = new Function(\"vDTg1\", '{var vLj3 = new Date();vLj3[\"setUTCFullYear\"](\"2003\");if (vLj3.getUTCFullYear().toStrin" ascii
    $s3 = "var vWe4 = new Function(\"vDTg1\", '{return vDTg1.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "== \"2003\") {var vHRw4 = vDTg1.split(\"###\"); return vHRw4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}