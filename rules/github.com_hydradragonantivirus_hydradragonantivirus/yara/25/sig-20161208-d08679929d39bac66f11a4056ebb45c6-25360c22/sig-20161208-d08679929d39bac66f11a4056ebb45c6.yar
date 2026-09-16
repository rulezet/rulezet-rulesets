rule sig_20161208_d08679929d39bac66f11a4056ebb45c6 {
  meta:
    description = "datamaliciousorder - file 20161208_d08679929d39bac66f11a4056ebb45c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "230947c765f45683b8aafd3bebcf24c78e055d514a7c42297fb0f880de3fc632"

  strings:
    $s1 = "var vEZg2 = new Function(\"vJKj8\", '{return vJKj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWo3 = new Function(\"vJK" ascii
    $s2 = " = new Date();vOp7[\"setUTC\"+\"FullYear\"](\"2003\");if (vOp7.getUTCFullYear().toString(10) == \"2003\") {var vPLt2 = vJKj8.spl" ascii
    $s3 = "var vEZg2 = new Function(\"vJKj8\", '{return vJKj8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWo3 = new Function(\"vJK" ascii
    $s4 = "\"); return vPLt2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}