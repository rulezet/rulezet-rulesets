rule sig_20161208_97a7aafb03d11019480abca245cd4f64 {
  meta:
    description = "datamaliciousorder - file 20161208_97a7aafb03d11019480abca245cd4f64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb0deee85ca837ef5f2175f60a0d53e258dbc01119bb69344f5d9be24e219304"

  strings:
    $s1 = "var vGd5 = new Function(\"vJd8\", '{return vJd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOl2 = new Function(\"vJd8\"" ascii
    $s2 = "ew Date();vJu9[\"setUTC\"+\"FullYear\"](\"2003\");if (vJu9.getUTCFullYear().toString(10) == \"2003\") {var vUq9 = vJd8.split(\"#" ascii
    $s3 = "var vGd5 = new Function(\"vJd8\", '{return vJd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOl2 = new Function(\"vJd8\"" ascii
    $s4 = "turn vUq9.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}