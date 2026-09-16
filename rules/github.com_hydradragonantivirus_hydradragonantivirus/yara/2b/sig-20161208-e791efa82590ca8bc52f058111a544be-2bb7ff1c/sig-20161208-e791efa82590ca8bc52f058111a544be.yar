rule sig_20161208_e791efa82590ca8bc52f058111a544be {
  meta:
    description = "datamaliciousorder - file 20161208_e791efa82590ca8bc52f058111a544be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47233857860caccff79db64a67feda22952bcf08a56be55ffc54fa8cd03fcdc2"

  strings:
    $s1 = "= new Date();vEl9[\"setUTC\"+\"FullYear\"](\"2003\");if (vEl9.getUTCFullYear().toString(10) == \"2003\") {var vASl2 = vSGi2.spli" ascii
    $s2 = "var vOe3 = new Function(\"vSGi2\", '{return vSGi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOx5 = new Function(\"vSGi" ascii
    $s3 = "var vOe3 = new Function(\"vSGi2\", '{return vSGi2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOx5 = new Function(\"vSGi" ascii
    $s4 = "); return vASl2.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}