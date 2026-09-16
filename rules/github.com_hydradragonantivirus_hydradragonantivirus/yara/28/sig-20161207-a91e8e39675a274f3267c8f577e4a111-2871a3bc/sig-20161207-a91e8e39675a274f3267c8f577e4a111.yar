rule sig_20161207_a91e8e39675a274f3267c8f577e4a111 {
  meta:
    description = "datamaliciousorder - file 20161207_a91e8e39675a274f3267c8f577e4a111.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbb663e3d0fde21a7896b931a88fe24e15a249ba8bdf17253b63e4da0780d27"

  strings:
    $s1 = "var vKr2 = new Function(\"vFi9\", '{var vCh0 = new Date();vCh0[\"setUTCFullYear\"](\"2003\");if (vCh0.getUTCFullYear().toString(" ascii
    $s2 = "var vKr2 = new Function(\"vFi9\", '{var vCh0 = new Date();vCh0[\"setUTCFullYear\"](\"2003\");if (vCh0.getUTCFullYear().toString(" ascii
    $s3 = "var vOp7 = new Function(\"vFi9\", '{return vFi9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vGf5 = vFi9.split(\"###\"); return vGf5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}