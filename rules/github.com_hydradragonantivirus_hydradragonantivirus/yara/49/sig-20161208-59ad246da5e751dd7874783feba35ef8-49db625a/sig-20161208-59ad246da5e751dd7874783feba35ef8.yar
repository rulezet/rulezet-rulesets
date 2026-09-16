rule sig_20161208_59ad246da5e751dd7874783feba35ef8 {
  meta:
    description = "datamaliciousorder - file 20161208_59ad246da5e751dd7874783feba35ef8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10640a6cb2c9d42980dbf7d76234772b763e9a60b9ca9aeed363755ed8d73f0e"

  strings:
    $s1 = " = new Date();vGv6[\"setUTC\"+\"FullYear\"](\"2003\");if (vGv6.getUTCFullYear().toString(10) == \"2003\") {var vZb0 = vMQa8.spli" ascii
    $s2 = "var vLAl2 = new Function(\"vMQa8\", '{return vMQa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOe7 = new Function(\"vMQ" ascii
    $s3 = "var vLAl2 = new Function(\"vMQa8\", '{return vMQa8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOe7 = new Function(\"vMQ" ascii
    $s4 = "); return vZb0.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}