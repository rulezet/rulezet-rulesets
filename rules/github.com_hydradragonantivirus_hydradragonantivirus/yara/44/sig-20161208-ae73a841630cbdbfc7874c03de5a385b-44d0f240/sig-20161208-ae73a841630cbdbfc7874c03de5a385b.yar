rule sig_20161208_ae73a841630cbdbfc7874c03de5a385b {
  meta:
    description = "datamaliciousorder - file 20161208_ae73a841630cbdbfc7874c03de5a385b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6a702eb2c7a0405d650662ca9e9b76d6f20c3f87528514b5aad101c3585216"

  strings:
    $s1 = "new Date();vYw4[\"setUTC\"+\"FullYear\"](\"2003\");if (vYw4.getUTCFullYear().toString(10) == \"2003\") {var vNBc7 = vPj3.split(" ascii
    $s2 = "var vZPu2 = new Function(\"vPj3\", '{return vPj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEz3 = new Function(\"vPj3" ascii
    $s3 = "var vZPu2 = new Function(\"vPj3\", '{return vPj3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vEz3 = new Function(\"vPj3" ascii
    $s4 = "return vNBc7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}