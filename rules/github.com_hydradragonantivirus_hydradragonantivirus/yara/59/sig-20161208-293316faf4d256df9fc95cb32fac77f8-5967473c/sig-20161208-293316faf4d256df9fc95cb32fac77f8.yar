rule sig_20161208_293316faf4d256df9fc95cb32fac77f8 {
  meta:
    description = "datamaliciousorder - file 20161208_293316faf4d256df9fc95cb32fac77f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e42ffdf2607441b6db57157f0d99cf4969ce818ce71709d0d6741d2dad086c92"

  strings:
    $s1 = "var vMv4 = new Function(\"vVo8\", '{return vVo8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFb6 = new Function(\"vVo8\"" ascii
    $s2 = "new Date();vDOm4[\"setUTC\"+\"FullYear\"](\"2003\");if (vDOm4.getUTCFullYear().toString(10) == \"2003\") {var vIz4 = vVo8.split(" ascii
    $s3 = "var vMv4 = new Function(\"vVo8\", '{return vVo8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vFb6 = new Function(\"vVo8\"" ascii
    $s4 = " return vIz4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}