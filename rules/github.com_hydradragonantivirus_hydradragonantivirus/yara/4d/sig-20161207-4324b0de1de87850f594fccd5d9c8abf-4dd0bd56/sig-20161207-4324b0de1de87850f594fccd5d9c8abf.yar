rule sig_20161207_4324b0de1de87850f594fccd5d9c8abf {
  meta:
    description = "datamaliciousorder - file 20161207_4324b0de1de87850f594fccd5d9c8abf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4cf6fd83ff10f1c6f5627af17dfa6efad587aa180df6ba8aa1bccb3914116d0"

  strings:
    $s1 = "var vYGk0 = new Function(\"vTp9\", '{var vZs4 = new Date();vZs4[\"setUTCFullYear\"](\"2003\");if (vZs4.getUTCFullYear().toString" ascii
    $s2 = "var vYGk0 = new Function(\"vTp9\", '{var vZs4 = new Date();vZs4[\"setUTCFullYear\"](\"2003\");if (vZs4.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vSm7 = vTp9.split(\"###\"); return vSm7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vVa8 = new Function(\"vTp9\", '{return vTp9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}