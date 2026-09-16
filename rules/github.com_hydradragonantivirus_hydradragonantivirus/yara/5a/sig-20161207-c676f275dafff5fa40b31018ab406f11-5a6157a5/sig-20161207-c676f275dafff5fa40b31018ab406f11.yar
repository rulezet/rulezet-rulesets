rule sig_20161207_c676f275dafff5fa40b31018ab406f11 {
  meta:
    description = "datamaliciousorder - file 20161207_c676f275dafff5fa40b31018ab406f11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d149c1c09a27f239cf873936212e795b54e7e39062677ce91ad30abf0a0e02b9"

  strings:
    $s1 = "var vLBm8 = new Function(\"vQk8\", '{var vZh1 = new Date();vZh1[\"setUTCFullYear\"](\"2003\");if (vZh1.getUTCFullYear().toString" ascii
    $s2 = "var vLBm8 = new Function(\"vQk8\", '{var vZh1 = new Date();vZh1[\"setUTCFullYear\"](\"2003\");if (vZh1.getUTCFullYear().toString" ascii
    $s3 = "var vSUe0 = new Function(\"vQk8\", '{return vQk8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "= \"2003\") {var vMf2 = vQk8.split(\"###\"); return vMf2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}