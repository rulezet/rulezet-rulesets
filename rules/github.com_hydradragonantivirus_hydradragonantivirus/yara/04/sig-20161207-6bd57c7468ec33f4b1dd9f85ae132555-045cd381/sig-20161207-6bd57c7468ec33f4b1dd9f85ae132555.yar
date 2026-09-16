rule sig_20161207_6bd57c7468ec33f4b1dd9f85ae132555 {
  meta:
    description = "datamaliciousorder - file 20161207_6bd57c7468ec33f4b1dd9f85ae132555.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f00251ff5e9d28da0be9c18024f9fd3a4d6d7e0e55412457cbe2a8f49b484e68"

  strings:
    $s1 = "= new Date();vFPp5[\"setUTCFullYear\"](\"2003\");if (vFPp5.getUTCFullYear().toString(10) == \"2003\") {var vCs6 = vHd8.split(\"#" ascii
    $s2 = "var vAFn0 = new Function(\"vHd8\", '{return vHd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vREw6 = new Function(\"vHd8" ascii
    $s3 = "var vAFn0 = new Function(\"vHd8\", '{return vHd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vREw6 = new Function(\"vHd8" ascii
    $s4 = "return vCs6.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}