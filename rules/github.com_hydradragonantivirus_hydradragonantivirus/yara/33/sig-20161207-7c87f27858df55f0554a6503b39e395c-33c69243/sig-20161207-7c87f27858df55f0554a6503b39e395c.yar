rule sig_20161207_7c87f27858df55f0554a6503b39e395c {
  meta:
    description = "datamaliciousorder - file 20161207_7c87f27858df55f0554a6503b39e395c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d4e4f0173730dbda7a2e6fff8e657206a561c802b837012227da59d65ae4427"

  strings:
    $s1 = "var vOQf1 = new Function(\"vCc0\", '{return vCc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZNn2 = new Function(\"vCc0" ascii
    $s2 = "= new Date();vIMj5[\"setUTCFullYear\"](\"2003\");if (vIMj5.getUTCFullYear().toString(10) == \"2003\") {var vFDy9 = vCc0.split(\"" ascii
    $s3 = " return vFDy9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vOQf1 = new Function(\"vCc0\", '{return vCc0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vZNn2 = new Function(\"vCc0" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}