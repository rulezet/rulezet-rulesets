rule sig_20161207_44e6a89f4a35e14fed82d58c67a7822e {
  meta:
    description = "datamaliciousorder - file 20161207_44e6a89f4a35e14fed82d58c67a7822e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c0a37a80c6776f1e1eac29ce1c3e64cc1db8ea6f72d8a9b3dc3fdc349a5a03b"

  strings:
    $s1 = "new Date();vIr2[\"setUTCFullYear\"](\"2003\");if (vIr2.getUTCFullYear().toString(10) == \"2003\") {var vWSj8 = vNw7.split(\"####" ascii
    $s2 = "var vSIg7 = new Function(\"vNw7\", '{return vNw7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHn4 = new Function(\"vNw7" ascii
    $s3 = "urn vWSj8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vSIg7 = new Function(\"vNw7\", '{return vNw7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHn4 = new Function(\"vNw7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}