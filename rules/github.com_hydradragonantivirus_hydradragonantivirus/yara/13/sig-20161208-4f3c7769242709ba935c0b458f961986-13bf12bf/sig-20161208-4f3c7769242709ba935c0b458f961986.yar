rule sig_20161208_4f3c7769242709ba935c0b458f961986 {
  meta:
    description = "datamaliciousorder - file 20161208_4f3c7769242709ba935c0b458f961986.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71605ad1e8e9310c7ff76a4ce4906dcde28c89b9f97306fbb4209c5e225cb161"

  strings:
    $s1 = "new Date();vNNf9[\"setUTC\"+\"FullYear\"](\"2003\");if (vNNf9.getUTCFullYear().toString(10) == \"2003\") {var vFYo9 = vYr6.split" ascii
    $s2 = "var vMa4 = new Function(\"vYr6\", '{return vYr6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIj9 = new Function(\"vYr6\"" ascii
    $s3 = "; return vFYo9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vMa4 = new Function(\"vYr6\", '{return vYr6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIj9 = new Function(\"vYr6\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}