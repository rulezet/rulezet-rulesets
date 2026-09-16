rule sig_20161207_997c4566a01a99cc0a2fbb082399fbab {
  meta:
    description = "datamaliciousorder - file 20161207_997c4566a01a99cc0a2fbb082399fbab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8ba6ee61b436dc629eba3897f47467316082c747945df15efa3eccaeca14a86"

  strings:
    $s1 = "var vGk8 = new Function(\"vIKy6\", '{var vURx1 = new Date();vURx1[\"setUTCFullYear\"](\"2003\");if (vURx1.getUTCFullYear().toStr" ascii
    $s2 = "var vGk8 = new Function(\"vIKy6\", '{var vURx1 = new Date();vURx1[\"setUTCFullYear\"](\"2003\");if (vURx1.getUTCFullYear().toStr" ascii
    $s3 = ") == \"2003\") {var vQZi0 = vIKy6.split(\"###\"); return vQZi0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vDc4 = new Function(\"vIKy6\", '{return vIKy6.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}