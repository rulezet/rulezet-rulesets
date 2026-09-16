rule sig_20161207_9964cd2e51a5b6766249ae63b6cd7eff {
  meta:
    description = "datamaliciousorder - file 20161207_9964cd2e51a5b6766249ae63b6cd7eff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3f90746e4bf38ab52f77b4e41050ee41806190064772112cd7307a095b4f6f0"

  strings:
    $s1 = " new Date();vVVg8[\"setUTCFullYear\"](\"2003\");if (vVVg8.getUTCFullYear().toString(10) == \"2003\") {var vBx1 = vLl0.split(\"##" ascii
    $s2 = "var vLx8 = new Function(\"vLl0\", '{return vLl0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFDn0 = new Function(\"vLl0" ascii
    $s3 = "eturn vBx1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vLx8 = new Function(\"vLl0\", '{return vLl0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFDn0 = new Function(\"vLl0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}