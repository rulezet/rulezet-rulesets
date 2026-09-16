rule sig_20161207_5b9e83bdd052486ecbc260a5ebb47f53 {
  meta:
    description = "datamaliciousorder - file 20161207_5b9e83bdd052486ecbc260a5ebb47f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de4aede3811e8a4198f38cfe4934f973fa9f577685c68705612f75844262d3ba"

  strings:
    $s1 = "var vQh1 = new Function(\"vXe3\", '{return vXe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIb0 = new Function(\"vXe3\"" ascii
    $s2 = "ew Date();vTw8[\"setUTCFullYear\"](\"2003\");if (vTw8.getUTCFullYear().toString(10) == \"2003\") {var vTq6 = vXe3.split(\"####\"" ascii
    $s3 = "var vQh1 = new Function(\"vXe3\", '{return vXe3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIb0 = new Function(\"vXe3\"" ascii
    $s4 = "n vTq6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}