rule sig_20161208_a56f1722b70c1ccb5a145be79808b28c {
  meta:
    description = "datamaliciousorder - file 20161208_a56f1722b70c1ccb5a145be79808b28c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c88e30b210c6dc5487684052aa7cc82487578844ea265c3f0f15c06bfa5ebbd7"

  strings:
    $s1 = "var vNLb6 = new Function(\"vWOv8\", '{return vWOv8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUl9 = new Function(\"vWO" ascii
    $s2 = "9 = new Date();vDPu9[\"setUTC\"+\"FullYear\"](\"2003\");if (vDPu9.getUTCFullYear().toString(10) == \"2003\") {var vUc0 = vWOv8.s" ascii
    $s3 = "##\"); return vUc0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNLb6 = new Function(\"vWOv8\", '{return vWOv8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUl9 = new Function(\"vWO" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}