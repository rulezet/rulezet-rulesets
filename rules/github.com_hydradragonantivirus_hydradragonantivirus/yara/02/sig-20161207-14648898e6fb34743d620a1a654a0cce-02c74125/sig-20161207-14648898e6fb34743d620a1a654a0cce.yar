rule sig_20161207_14648898e6fb34743d620a1a654a0cce {
  meta:
    description = "datamaliciousorder - file 20161207_14648898e6fb34743d620a1a654a0cce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a342384a4c006cba80ca502c0cae159673f3eeeea060b846b21875d368a13e2"

  strings:
    $s1 = "var vBXt9 = new Function(\"vPHc5\", '{var vLFo7 = new Date();vLFo7[\"setUTCFullYear\"](\"2003\");if (vLFo7.getUTCFullYear().toSt" ascii
    $s2 = "var vBXt9 = new Function(\"vPHc5\", '{var vLFo7 = new Date();vLFo7[\"setUTCFullYear\"](\"2003\");if (vLFo7.getUTCFullYear().toSt" ascii
    $s3 = "0) == \"2003\") {var vNc1 = vPHc5.split(\"###\"); return vNc1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vSg9 = new Function(\"vPHc5\", '{return vPHc5.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}