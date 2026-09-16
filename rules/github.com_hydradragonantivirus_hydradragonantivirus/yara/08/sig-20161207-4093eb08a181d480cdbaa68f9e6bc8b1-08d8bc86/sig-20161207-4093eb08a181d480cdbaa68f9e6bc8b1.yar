rule sig_20161207_4093eb08a181d480cdbaa68f9e6bc8b1 {
  meta:
    description = "datamaliciousorder - file 20161207_4093eb08a181d480cdbaa68f9e6bc8b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd9f1e6c68563c44879dcb79d3b84ef9b0dc92c1387d2026744bf637500dcce3"

  strings:
    $s1 = "var vVXb5 = new Function(\"vOk9\", '{var vBBd7 = new Date();vBBd7[\"setUTCFullYear\"](\"2003\");if (vBBd7.getUTCFullYear().toStr" ascii
    $s2 = "var vVXb5 = new Function(\"vOk9\", '{var vBBd7 = new Date();vBBd7[\"setUTCFullYear\"](\"2003\");if (vBBd7.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vYSn0 = vOk9.split(\"###\"); return vYSn0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vAo8 = new Function(\"vOk9\", '{return vOk9.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}