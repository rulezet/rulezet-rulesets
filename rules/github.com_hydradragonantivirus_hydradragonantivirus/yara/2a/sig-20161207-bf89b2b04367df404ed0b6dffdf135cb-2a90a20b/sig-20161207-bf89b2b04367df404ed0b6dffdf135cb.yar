rule sig_20161207_bf89b2b04367df404ed0b6dffdf135cb {
  meta:
    description = "datamaliciousorder - file 20161207_bf89b2b04367df404ed0b6dffdf135cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f94052a3909e68a9edf9c8f3a56e45b775d64d0b77de16b34f0bb944e6c1b83e"

  strings:
    $s1 = "var vJn4 = new Function(\"vZOd3\", '{return vZOd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCp7 = new Function(\"vZOd" ascii
    $s2 = "= new Date();vAy3[\"setUTCFullYear\"](\"2003\");if (vAy3.getUTCFullYear().toString(10) == \"2003\") {var vOXo0 = vZOd3.split(\"#" ascii
    $s3 = "return vOXo0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vJn4 = new Function(\"vZOd3\", '{return vZOd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vCp7 = new Function(\"vZOd" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}