rule sig_20161208_0a5d214fac6c97ce52c19b0a2d24339a {
  meta:
    description = "datamaliciousorder - file 20161208_0a5d214fac6c97ce52c19b0a2d24339a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "542a39921e35680e4f01a9dd53ae4f4210d21926f947fbc78cd50afbad68e913"

  strings:
    $s1 = "var vUi3 = new Function(\"vLf3\", '{return vLf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJSr9 = new Function(\"vLf3" ascii
    $s2 = "new Date();vFf8[\"setUTC\"+\"FullYear\"](\"2003\");if (vFf8.getUTCFullYear().toString(10) == \"2003\") {var vTf3 = vLf3.split(\"" ascii
    $s3 = "eturn vTf3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vUi3 = new Function(\"vLf3\", '{return vLf3[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJSr9 = new Function(\"vLf3" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}