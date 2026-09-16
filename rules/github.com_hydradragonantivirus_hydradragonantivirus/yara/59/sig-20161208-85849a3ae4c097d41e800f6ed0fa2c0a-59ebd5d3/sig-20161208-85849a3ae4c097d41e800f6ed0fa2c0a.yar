rule sig_20161208_85849a3ae4c097d41e800f6ed0fa2c0a {
  meta:
    description = "datamaliciousorder - file 20161208_85849a3ae4c097d41e800f6ed0fa2c0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c629f80d431c6847c08e15657b3618ba8a041768a55750f823db33e26f0eca78"

  strings:
    $s1 = "var vFPj0 = new Function(\"vRf2\", '{return vRf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vICt1 = new Function(\"vRf2" ascii
    $s2 = "= new Date();vUYa2[\"setUTC\"+\"FullYear\"](\"2003\");if (vUYa2.getUTCFullYear().toString(10) == \"2003\") {var vRDf0 = vRf2.spl" ascii
    $s3 = "\"); return vRDf0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFPj0 = new Function(\"vRf2\", '{return vRf2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vICt1 = new Function(\"vRf2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}