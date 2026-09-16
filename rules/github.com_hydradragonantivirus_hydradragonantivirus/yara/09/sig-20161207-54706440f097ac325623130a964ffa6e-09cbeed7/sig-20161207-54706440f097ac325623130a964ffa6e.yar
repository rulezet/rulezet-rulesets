rule sig_20161207_54706440f097ac325623130a964ffa6e {
  meta:
    description = "datamaliciousorder - file 20161207_54706440f097ac325623130a964ffa6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12588e8afc65cf82f0d7ec6fe2629f9511dfd0bf49b72f9c155b81bfc7a298e8"

  strings:
    $s1 = "var vQv6 = new Function(\"vJVt8\", '{var vMKx4 = new Date();vMKx4[\"setUTCFullYear\"](\"2003\");if (vMKx4.getUTCFullYear().toStr" ascii
    $s2 = "var vQv6 = new Function(\"vJVt8\", '{var vMKx4 = new Date();vMKx4[\"setUTCFullYear\"](\"2003\");if (vMKx4.getUTCFullYear().toStr" ascii
    $s3 = "var vNz5 = new Function(\"vJVt8\", '{return vJVt8.split(\",\").join(\"\");};');" fullword ascii
    $s4 = ") == \"2003\") {var vTDk1 = vJVt8.split(\"###\"); return vTDk1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}