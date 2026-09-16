rule sig_20161207_f9a4f6826620c7eae59530393291de2c {
  meta:
    description = "datamaliciousorder - file 20161207_f9a4f6826620c7eae59530393291de2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06ed8d8b7ffd81d3f12f62272c8f2e9005956cb38001c82f981b3dd618827347"

  strings:
    $s1 = "var vVQj0 = new Function(\"vJXl0\", '{var vTEk7 = new Date();vTEk7[\"setUTCFullYear\"](\"2003\");if (vTEk7.getUTCFullYear().toSt" ascii
    $s2 = "var vVQj0 = new Function(\"vJXl0\", '{var vTEk7 = new Date();vTEk7[\"setUTCFullYear\"](\"2003\");if (vTEk7.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vBLb1 = vJXl0.split(\"###\"); return vBLb1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vPc4 = new Function(\"vJXl0\", '{return vJXl0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}