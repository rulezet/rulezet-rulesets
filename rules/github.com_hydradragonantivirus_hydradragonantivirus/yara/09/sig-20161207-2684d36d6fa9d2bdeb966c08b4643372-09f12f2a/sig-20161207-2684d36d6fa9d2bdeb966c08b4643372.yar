rule sig_20161207_2684d36d6fa9d2bdeb966c08b4643372 {
  meta:
    description = "datamaliciousorder - file 20161207_2684d36d6fa9d2bdeb966c08b4643372.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8270c761b25f9606b1e605ae5b53fa2cfa5ae27115bcc7bed9c71ab6444fdc8"

  strings:
    $s1 = "8 = new Date();vDDk8[\"setUTCFullYear\"](\"2003\");if (vDDk8.getUTCFullYear().toString(10) == \"2003\") {var vXNf6 = vDBh9.split" ascii
    $s2 = "var vYe4 = new Function(\"vDBh9\", '{return vDBh9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRYq9 = new Function(\"vDB" ascii
    $s3 = "\"); return vXNf6.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYe4 = new Function(\"vDBh9\", '{return vDBh9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRYq9 = new Function(\"vDB" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}