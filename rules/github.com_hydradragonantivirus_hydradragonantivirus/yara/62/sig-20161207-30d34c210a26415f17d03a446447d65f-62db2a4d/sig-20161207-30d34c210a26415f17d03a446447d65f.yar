rule sig_20161207_30d34c210a26415f17d03a446447d65f {
  meta:
    description = "datamaliciousorder - file 20161207_30d34c210a26415f17d03a446447d65f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d105b6c3d8dcdebd669d93e51df141038156decabcb424fe8280d8527f351fc"

  strings:
    $s1 = "var vFv1 = new Function(\"vVAb0\", '{var vWQq1 = new Date();vWQq1[\"setUTCFullYear\"](\"2003\");if (vWQq1.getUTCFullYear().toStr" ascii
    $s2 = "var vFv1 = new Function(\"vVAb0\", '{var vWQq1 = new Date();vWQq1[\"setUTCFullYear\"](\"2003\");if (vWQq1.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vCNl1 = vVAb0.split(\"###\"); return vCNl1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vBi7 = new Function(\"vVAb0\", '{return vVAb0.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}