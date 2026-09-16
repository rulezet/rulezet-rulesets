rule sig_20161207_fb1d8a91a5c15d4699a1ea2e730b51e6 {
  meta:
    description = "datamaliciousorder - file 20161207_fb1d8a91a5c15d4699a1ea2e730b51e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d223f4d2be0f4dc202ff7904875baac7aed70ee29326156a2edcd324d4c14366"

  strings:
    $s1 = "var vVb5 = new Function(\"vTc1\", '{return vTc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPy5 = new Function(\"vTc1\"" ascii
    $s2 = "ew Date();vAh6[\"setUTCFullYear\"](\"2003\");if (vAh6.getUTCFullYear().toString(10) == \"2003\") {var vDAk1 = vTc1.split(\"####" ascii
    $s3 = "var vVb5 = new Function(\"vTc1\", '{return vTc1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vPy5 = new Function(\"vTc1\"" ascii
    $s4 = "rn vDAk1.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}