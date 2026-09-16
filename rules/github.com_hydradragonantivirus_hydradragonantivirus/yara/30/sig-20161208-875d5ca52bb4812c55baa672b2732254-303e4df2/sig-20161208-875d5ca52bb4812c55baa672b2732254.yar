rule sig_20161208_875d5ca52bb4812c55baa672b2732254 {
  meta:
    description = "datamaliciousorder - file 20161208_875d5ca52bb4812c55baa672b2732254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd63ed3a48bb53f32f87b41a910d403b81c7e9ee08db5e5eebf0a1350d1b4e1e"

  strings:
    $s1 = "var vDMj0 = new Function(\"vRm7\", '{return vRm7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vODo0 = new Function(\"vRm7" ascii
    $s2 = "= new Date();vBFl1[\"setUTC\"+\"FullYear\"](\"2003\");if (vBFl1.getUTCFullYear().toString(10) == \"2003\") {var vAz7 = vRm7.spli" ascii
    $s3 = "var vDMj0 = new Function(\"vRm7\", '{return vRm7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vODo0 = new Function(\"vRm7" ascii
    $s4 = "); return vAz7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}