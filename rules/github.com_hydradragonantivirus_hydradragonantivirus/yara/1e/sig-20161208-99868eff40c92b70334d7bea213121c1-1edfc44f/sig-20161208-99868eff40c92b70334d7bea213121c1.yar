rule sig_20161208_99868eff40c92b70334d7bea213121c1 {
  meta:
    description = "datamaliciousorder - file 20161208_99868eff40c92b70334d7bea213121c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4fa92034ca31d6d9d433f2f1c3881d286e97b86014c495783dfa7d672646d73"

  strings:
    $s1 = "= new Date();vRy3[\"setUTC\"+\"FullYear\"](\"2003\");if (vRy3.getUTCFullYear().toString(10) == \"2003\") {var vHNk1 = vHZd8.spli" ascii
    $s2 = "var vIr1 = new Function(\"vHZd8\", '{return vHZd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPg7 = new Function(\"vHZd" ascii
    $s3 = "var vIr1 = new Function(\"vHZd8\", '{return vHZd8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPg7 = new Function(\"vHZd" ascii
    $s4 = "); return vHNk1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}