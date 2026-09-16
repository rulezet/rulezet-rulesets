rule sig_20161208_2d78902aecce17b7946cb2c0ebcd207e {
  meta:
    description = "datamaliciousorder - file 20161208_2d78902aecce17b7946cb2c0ebcd207e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf4c9e0ad3ffd4ee98ef58a1063ae7a6266691f34d6e6574fad1173b4412009c"

  strings:
    $s1 = " = new Date();vAy5[\"setUTC\"+\"FullYear\"](\"2003\");if (vAy5.getUTCFullYear().toString(10) == \"2003\") {var vZIq4 = vJBh6.spl" ascii
    $s2 = "var vRg9 = new Function(\"vJBh6\", '{return vJBh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIUl2 = new Function(\"vJB" ascii
    $s3 = "\"); return vZIq4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRg9 = new Function(\"vJBh6\", '{return vJBh6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vIUl2 = new Function(\"vJB" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}