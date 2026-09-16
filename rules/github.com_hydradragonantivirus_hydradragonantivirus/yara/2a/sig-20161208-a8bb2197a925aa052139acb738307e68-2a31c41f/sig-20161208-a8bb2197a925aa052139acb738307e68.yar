rule sig_20161208_a8bb2197a925aa052139acb738307e68 {
  meta:
    description = "datamaliciousorder - file 20161208_a8bb2197a925aa052139acb738307e68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0aec0db44775e31f82033cee1f984dfbd3c4cceab52f523f645914edfa1efa7"

  strings:
    $s1 = " = new Date();vCj3[\"setUTC\"+\"FullYear\"](\"2003\");if (vCj3.getUTCFullYear().toString(10) == \"2003\") {var vARs3 = vPJj6.spl" ascii
    $s2 = "var vHw1 = new Function(\"vPJj6\", '{return vPJj6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOYi9 = new Function(\"vPJ" ascii
    $s3 = "var vHw1 = new Function(\"vPJj6\", '{return vPJj6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOYi9 = new Function(\"vPJ" ascii
    $s4 = "\"); return vARs3.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}