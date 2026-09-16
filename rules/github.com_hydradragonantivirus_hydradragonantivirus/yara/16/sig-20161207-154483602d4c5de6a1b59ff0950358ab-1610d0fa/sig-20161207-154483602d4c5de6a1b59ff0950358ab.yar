rule sig_20161207_154483602d4c5de6a1b59ff0950358ab {
  meta:
    description = "datamaliciousorder - file 20161207_154483602d4c5de6a1b59ff0950358ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aad61ca505762d67c453ce5de7c9623d59261fa14d9ed2ca8381bc55114b3106"

  strings:
    $s1 = "var vYOm3 = new Function(\"vLGl3\", '{var vFl3 = new Date();vFl3[\"setUTCFullYear\"](\"2003\");if (vFl3.getUTCFullYear().toStrin" ascii
    $s2 = "var vYOm3 = new Function(\"vLGl3\", '{var vFl3 = new Date();vFl3[\"setUTCFullYear\"](\"2003\");if (vFl3.getUTCFullYear().toStrin" ascii
    $s3 = "== \"2003\") {var vVk0 = vLGl3.split(\"###\"); return vVk0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vDIt9 = new Function(\"vLGl3\", '{return vLGl3.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}