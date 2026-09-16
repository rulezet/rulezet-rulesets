rule sig_20161208_e22265640f9a1e670ef24a2bc1039b07 {
  meta:
    description = "datamaliciousorder - file 20161208_e22265640f9a1e670ef24a2bc1039b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cc9ce7e9021a46a92ff9675b134cfe75ea4b34c72adbc64cfad845a7d725070"

  strings:
    $s1 = "var vHQe6 = new Function(\"vUd1\", '{return vUd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZy6 = new Function(\"vUd1" ascii
    $s2 = "new Date();vIs3[\"setUTC\"+\"FullYear\"](\"2003\");if (vIs3.getUTCFullYear().toString(10) == \"2003\") {var vXx4 = vUd1.split(\"" ascii
    $s3 = "eturn vXx4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vHQe6 = new Function(\"vUd1\", '{return vUd1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZy6 = new Function(\"vUd1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}