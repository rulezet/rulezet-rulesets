rule sig_20161207_a86d16a1561e2a626b81e1284fd27fbd {
  meta:
    description = "datamaliciousorder - file 20161207_a86d16a1561e2a626b81e1284fd27fbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5230228358c0be7b2a5ab8a816f479381e47a4676f76045df6d9de87151c27d"

  strings:
    $s1 = "var vOCo8 = new Function(\"vFNe6\", '{return vFNe6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOWp9 = new Function(\"vF" ascii
    $s2 = "0 = new Date();vZh0[\"setUTCFullYear\"](\"2003\");if (vZh0.getUTCFullYear().toString(10) == \"2003\") {var vWq2 = vFNe6.split(\"" ascii
    $s3 = "var vOCo8 = new Function(\"vFNe6\", '{return vFNe6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOWp9 = new Function(\"vF" ascii
    $s4 = " return vWq2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}