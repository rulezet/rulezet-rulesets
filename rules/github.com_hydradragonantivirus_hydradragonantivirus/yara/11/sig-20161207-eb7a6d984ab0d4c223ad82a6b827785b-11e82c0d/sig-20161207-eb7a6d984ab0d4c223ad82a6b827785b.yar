rule sig_20161207_eb7a6d984ab0d4c223ad82a6b827785b {
  meta:
    description = "datamaliciousorder - file 20161207_eb7a6d984ab0d4c223ad82a6b827785b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "192d10c9f3f917a4d968daab1dfb68391f3b1d551e67c376f0a3206c4b0c9498"

  strings:
    $s1 = "var vTo5 = new Function(\"vPDl4\", '{var vWFu2 = new Date();vWFu2[\"setUTCFullYear\"](\"2003\");if (vWFu2.getUTCFullYear().toStr" ascii
    $s2 = "var vTo5 = new Function(\"vPDl4\", '{var vWFu2 = new Date();vWFu2[\"setUTCFullYear\"](\"2003\");if (vWFu2.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vCIt1 = vPDl4.split(\"###\"); return vCIt1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vEEb3 = new Function(\"vPDl4\", '{return vPDl4.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}