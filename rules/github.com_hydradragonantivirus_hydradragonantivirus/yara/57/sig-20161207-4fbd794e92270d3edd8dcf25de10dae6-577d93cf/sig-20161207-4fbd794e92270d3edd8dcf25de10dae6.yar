rule sig_20161207_4fbd794e92270d3edd8dcf25de10dae6 {
  meta:
    description = "datamaliciousorder - file 20161207_4fbd794e92270d3edd8dcf25de10dae6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2df51a9580820caa56f2cfa4d12c5886bb8c583d062cf81c74e9c437a58c1f"

  strings:
    $s1 = "var vFo1 = new Function(\"vPBv5\", '{return vPBv5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEi8 = new Function(\"vPBv" ascii
    $s2 = " = new Date();vCGy2[\"setUTCFullYear\"](\"2003\");if (vCGy2.getUTCFullYear().toString(10) == \"2003\") {var vTAs3 = vPBv5.split(" ascii
    $s3 = "); return vTAs3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFo1 = new Function(\"vPBv5\", '{return vPBv5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEi8 = new Function(\"vPBv" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}