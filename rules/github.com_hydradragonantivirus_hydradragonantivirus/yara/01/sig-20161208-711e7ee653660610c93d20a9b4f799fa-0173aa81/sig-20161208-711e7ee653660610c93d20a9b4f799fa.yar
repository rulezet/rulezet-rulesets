rule sig_20161208_711e7ee653660610c93d20a9b4f799fa {
  meta:
    description = "datamaliciousorder - file 20161208_711e7ee653660610c93d20a9b4f799fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c74268199626a77b56e3700a6cf3ca3e368c382ce2d2de8d6470142b5941c90d"

  strings:
    $s1 = "var vSn5 = new Function(\"vTIs1\", '{return vTIs1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIo0 = new Function(\"vTIs" ascii
    $s2 = " = new Date();vHDb2[\"setUTC\"+\"FullYear\"](\"2003\");if (vHDb2.getUTCFullYear().toString(10) == \"2003\") {var vJLs4 = vTIs1.s" ascii
    $s3 = "var vSn5 = new Function(\"vTIs1\", '{return vTIs1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIo0 = new Function(\"vTIs" ascii
    $s4 = "##\"); return vJLs4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}