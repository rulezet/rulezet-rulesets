rule sig_20161208_106546f9ad7b6747a7f880d90973aa04 {
  meta:
    description = "datamaliciousorder - file 20161208_106546f9ad7b6747a7f880d90973aa04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31aa14f17c8d24aceda8af609ce6190964c5c78bdfe74a01f9f2e416bb8ac5ce"

  strings:
    $s1 = " = new Date();vJs3[\"setUTC\"+\"FullYear\"](\"2003\");if (vJs3.getUTCFullYear().toString(10) == \"2003\") {var vTAz5 = vLLh8.spl" ascii
    $s2 = "var vRu7 = new Function(\"vLLh8\", '{return vLLh8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHCa7 = new Function(\"vLL" ascii
    $s3 = "\"); return vTAz5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRu7 = new Function(\"vLLh8\", '{return vLLh8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vHCa7 = new Function(\"vLL" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}