rule sig_20161207_4519a61a9d7dd0f3fd4b0d4ae7becfd8 {
  meta:
    description = "datamaliciousorder - file 20161207_4519a61a9d7dd0f3fd4b0d4ae7becfd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ac93e5b463dfc5cadebff0f8668f3c128711b0379003b1d10c87585c903f20"

  strings:
    $s1 = "var vCHr7 = new Function(\"vLKd3\", '{return vLKd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOn0 = new Function(\"vLK" ascii
    $s2 = " = new Date();vSi1[\"setUTCFullYear\"](\"2003\");if (vSi1.getUTCFullYear().toString(10) == \"2003\") {var vOm40 = vLKd3.split(\"" ascii
    $s3 = "var vCHr7 = new Function(\"vLKd3\", '{return vLKd3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOn0 = new Function(\"vLK" ascii
    $s4 = " return vOm40.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}