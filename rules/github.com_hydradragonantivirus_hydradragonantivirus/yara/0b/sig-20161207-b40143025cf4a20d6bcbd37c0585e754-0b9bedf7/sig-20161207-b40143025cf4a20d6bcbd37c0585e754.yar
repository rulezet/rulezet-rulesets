rule sig_20161207_b40143025cf4a20d6bcbd37c0585e754 {
  meta:
    description = "datamaliciousorder - file 20161207_b40143025cf4a20d6bcbd37c0585e754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e232b8c4633aac5fff79f2dcc267ab64a947493f1d57ab8998a6b7de2c463037"

  strings:
    $s1 = "var vUt5 = new Function(\"vDl7\", '{var vTk2 = new Date();vTk2[\"setUTCFullYear\"](\"2003\");if (vTk2.getUTCFullYear().toString(" ascii
    $s2 = "var vUt5 = new Function(\"vDl7\", '{var vTk2 = new Date();vTk2[\"setUTCFullYear\"](\"2003\");if (vTk2.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vXn3 = vDl7.split(\"###\"); return vXn3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAy5 = new Function(\"vDl7\", '{return vDl7.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}