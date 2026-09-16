rule sig_20161208_d6c583a44033f9174ae827a7a254f42c {
  meta:
    description = "datamaliciousorder - file 20161208_d6c583a44033f9174ae827a7a254f42c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76bebd583c27ef2f60d9fd78cfdc05cd83f32ff3de2922f6c5926d73478356a1"

  strings:
    $s1 = "= new Date();vOr0[\"setUTC\"+\"FullYear\"](\"2003\");if (vOr0.getUTCFullYear().toString(10) == \"2003\") {var vYUm4 = vXJa4.spli" ascii
    $s2 = "var vCq7 = new Function(\"vXJa4\", '{return vXJa4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWv4 = new Function(\"vXJa" ascii
    $s3 = "var vCq7 = new Function(\"vXJa4\", '{return vXJa4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWv4 = new Function(\"vXJa" ascii
    $s4 = "); return vYUm4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}