rule sig_20161207_7728a29d36b093701ba04396b55d466a {
  meta:
    description = "datamaliciousorder - file 20161207_7728a29d36b093701ba04396b55d466a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ca5519c5385ab744bacb31dfcc8ce1451356a38a3fce0d0b6e8de028ade157b"

  strings:
    $s1 = "var vFz8 = new Function(\"vOo2\", '{var vBt6 = new Date();vBt6[\"setUTCFullYear\"](\"2003\");if (vBt6.getUTCFullYear().toString(" ascii
    $s2 = "var vFz8 = new Function(\"vOo2\", '{var vBt6 = new Date();vBt6[\"setUTCFullYear\"](\"2003\");if (vBt6.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vOv7 = vOo2.split(\"###\"); return vOv7.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "var vIr3 = new Function(\"vOo2\", '{return vOo2.split(\",\").join(\"\");};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}