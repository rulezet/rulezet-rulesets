rule sig_20161208_5460f98aba4a1d168d524a5d6024bccc {
  meta:
    description = "datamaliciousorder - file 20161208_5460f98aba4a1d168d524a5d6024bccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2eff2547ca23447e47439397559774a86652468a019d5c4e6bf3bf8808c62a8"

  strings:
    $s1 = "var vSx2 = new Function(\"vYTe5\", '{return vYTe5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJUo3 = new Function(\"vYT" ascii
    $s2 = "5 = new Date();vPYo5[\"setUTC\"+\"FullYear\"](\"2003\");if (vPYo5.getUTCFullYear().toString(10) == \"2003\") {var vBu4 = vYTe5.s" ascii
    $s3 = "var vSx2 = new Function(\"vYTe5\", '{return vYTe5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJUo3 = new Function(\"vYT" ascii
    $s4 = "##\"); return vBu4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}