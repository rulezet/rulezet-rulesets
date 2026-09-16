rule sig_20161208_f7bd5e361fd6f9c91724baa42f586ce7 {
  meta:
    description = "datamaliciousorder - file 20161208_f7bd5e361fd6f9c91724baa42f586ce7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86afad7bf1f0ebefb5ac1687c2732077a8008b4935c6048910083b6d043324a5"

  strings:
    $s1 = "var vPm7 = new Function(\"vHIx4\", '{return vHIx4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDa2 = new Function(\"vHIx" ascii
    $s2 = "= new Date();vZn5[\"setUTC\"+\"FullYear\"](\"2003\");if (vZn5.getUTCFullYear().toString(10) == \"2003\") {var vOVg4 = vHIx4.spli" ascii
    $s3 = "var vPm7 = new Function(\"vHIx4\", '{return vHIx4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDa2 = new Function(\"vHIx" ascii
    $s4 = "); return vOVg4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}