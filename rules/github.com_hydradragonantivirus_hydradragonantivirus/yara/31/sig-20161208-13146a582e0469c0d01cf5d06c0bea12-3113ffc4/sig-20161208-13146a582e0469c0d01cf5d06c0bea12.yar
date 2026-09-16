rule sig_20161208_13146a582e0469c0d01cf5d06c0bea12 {
  meta:
    description = "datamaliciousorder - file 20161208_13146a582e0469c0d01cf5d06c0bea12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15f8c89e3d802b48e410ecd4a1e25336fb58a9691632136941af0645ac0de7a7"

  strings:
    $s1 = "var vPs7 = new Function(\"vEHj6\", '{return vEHj6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUg6 = new Function(\"vEHj" ascii
    $s2 = " = new Date();vFTf0[\"setUTC\"+\"FullYear\"](\"2003\");if (vFTf0.getUTCFullYear().toString(10) == \"2003\") {var vEBu7 = vEHj6.s" ascii
    $s3 = "var vPs7 = new Function(\"vEHj6\", '{return vEHj6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUg6 = new Function(\"vEHj" ascii
    $s4 = "##\"); return vEBu7.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}