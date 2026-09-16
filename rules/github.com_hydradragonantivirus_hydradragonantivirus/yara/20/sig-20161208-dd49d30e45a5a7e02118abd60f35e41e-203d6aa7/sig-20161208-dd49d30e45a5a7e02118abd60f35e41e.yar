rule sig_20161208_dd49d30e45a5a7e02118abd60f35e41e {
  meta:
    description = "datamaliciousorder - file 20161208_dd49d30e45a5a7e02118abd60f35e41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "962b6a2a9518da1f6508403d74126f17e67a4b2f062555ee0957593f3cb319c1"

  strings:
    $s1 = "var vVKs3 = new Function(\"vZy3\", '{return vZy3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXz0 = new Function(\"vZy3" ascii
    $s2 = " new Date();vZIc6[\"setUTC\"+\"FullYear\"](\"2003\");if (vZIc6.getUTCFullYear().toString(10) == \"2003\") {var vUr0 = vZy3.split" ascii
    $s3 = "var vVKs3 = new Function(\"vZy3\", '{return vZy3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vXz0 = new Function(\"vZy3" ascii
    $s4 = "; return vUr0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}