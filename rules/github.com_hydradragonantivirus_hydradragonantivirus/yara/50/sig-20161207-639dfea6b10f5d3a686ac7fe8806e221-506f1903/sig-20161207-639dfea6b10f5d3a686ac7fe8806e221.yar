rule sig_20161207_639dfea6b10f5d3a686ac7fe8806e221 {
  meta:
    description = "datamaliciousorder - file 20161207_639dfea6b10f5d3a686ac7fe8806e221.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59693ae99467ca450fccf5d4b1215598501995c71858ccc926a112ade1c823aa"

  strings:
    $s1 = "var vFu6 = new Function(\"vSe3\", '{var vYb9 = new Date();vYb9[\"setUTCFullYear\"](\"2003\");if (vYb9.getUTCFullYear().toString(" ascii
    $s2 = "var vFu6 = new Function(\"vSe3\", '{var vYb9 = new Date();vYb9[\"setUTCFullYear\"](\"2003\");if (vYb9.getUTCFullYear().toString(" ascii
    $s3 = "var vHl2 = new Function(\"vSe3\", '{return vSe3.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vBUd4 = vSe3.split(\"###\"); return vBUd4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}