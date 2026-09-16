rule sig_20161207_b6be8596588a60d6b40649c89b4a1a9f {
  meta:
    description = "datamaliciousorder - file 20161207_b6be8596588a60d6b40649c89b4a1a9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f812d7236af2e4b8e65e29d65ad9b19e92cdf3bd2b15f51c1da2fb042472efe"

  strings:
    $s1 = "9 = new Date();vQz9[\"setUTCFullYear\"](\"2003\");if (vQz9.getUTCFullYear().toString(10) == \"2003\") {var vSVg9 = vCAo6.split(" ascii
    $s2 = "var vNAg1 = new Function(\"vCAo6\", '{return vCAo6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQDw0 = new Function(\"vC" ascii
    $s3 = "; return vSVg9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNAg1 = new Function(\"vCAo6\", '{return vCAo6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQDw0 = new Function(\"vC" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}