rule sig_20161208_d1527d5a9ed2bcfa24cc4b3daae2098c {
  meta:
    description = "datamaliciousorder - file 20161208_d1527d5a9ed2bcfa24cc4b3daae2098c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7dc0ee257f2226f721f9921f8fb42fb4587ad3dae8c54bd22610d334996a986"

  strings:
    $s1 = "var vICg8 = new Function(\"vIs9\", '{return vIs9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKOr8 = new Function(\"vIs9" ascii
    $s2 = " new Date();vHd9[\"setUTC\"+\"FullYear\"](\"2003\");if (vHd9.getUTCFullYear().toString(10) == \"2003\") {var vZUl2 = vIs9.split(" ascii
    $s3 = " return vZUl2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vICg8 = new Function(\"vIs9\", '{return vIs9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vKOr8 = new Function(\"vIs9" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}