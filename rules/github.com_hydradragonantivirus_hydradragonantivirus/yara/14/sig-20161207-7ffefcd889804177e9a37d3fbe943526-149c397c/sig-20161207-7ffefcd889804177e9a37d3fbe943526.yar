rule sig_20161207_7ffefcd889804177e9a37d3fbe943526 {
  meta:
    description = "datamaliciousorder - file 20161207_7ffefcd889804177e9a37d3fbe943526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "998ffbc9a8db77d52003a8733badb55a623c5fa465165be19b19da76aa1f9d43"

  strings:
    $s1 = "var vOc5 = new Function(\"vEy7\", '{var vOp7 = new Date();vOp7[\"setUTCFullYear\"](\"2003\");if (vOp7.getUTCFullYear().toString(" ascii
    $s2 = "var vOc5 = new Function(\"vEy7\", '{var vOp7 = new Date();vOp7[\"setUTCFullYear\"](\"2003\");if (vOp7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vIKb9 = vEy7.split(\"###\"); return vIKb9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vDYb1 = new Function(\"vEy7\", '{return vEy7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}