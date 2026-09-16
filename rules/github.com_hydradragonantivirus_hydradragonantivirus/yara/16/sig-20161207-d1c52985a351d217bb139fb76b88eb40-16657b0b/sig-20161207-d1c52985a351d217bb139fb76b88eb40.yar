rule sig_20161207_d1c52985a351d217bb139fb76b88eb40 {
  meta:
    description = "datamaliciousorder - file 20161207_d1c52985a351d217bb139fb76b88eb40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d07e1308d52be9a94205343d2519a0a16b551dda494c9bd70744bcebd47b9f22"

  strings:
    $s1 = "var vGHa0 = new Function(\"vAo6\", '{var vZs1 = new Date();vZs1[\"setUTCFullYear\"](\"2003\");if (vZs1.getUTCFullYear().toString" ascii
    $s2 = "var vGHa0 = new Function(\"vAo6\", '{var vZs1 = new Date();vZs1[\"setUTCFullYear\"](\"2003\");if (vZs1.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vLw3 = vAo6.split(\"###\"); return vLw3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vMa2 = new Function(\"vAo6\", '{return vAo6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}