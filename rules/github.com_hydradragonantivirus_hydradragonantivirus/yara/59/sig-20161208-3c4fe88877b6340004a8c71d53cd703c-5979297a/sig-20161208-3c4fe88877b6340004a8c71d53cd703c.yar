rule sig_20161208_3c4fe88877b6340004a8c71d53cd703c {
  meta:
    description = "datamaliciousorder - file 20161208_3c4fe88877b6340004a8c71d53cd703c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9dbdaeb6b6b02a4259827b3a4d779f80b5120085e20ba01b86f2ea1824fa1d4d"

  strings:
    $s1 = "var vCo2 = new Function(\"vWHg2\", '{return vWHg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLIf4 = new Function(\"vWH" ascii
    $s2 = " = new Date();vBn6[\"setUTC\"+\"FullYear\"](\"2003\");if (vBn6.getUTCFullYear().toString(10) == \"2003\") {var vEBo4 = vWHg2.spl" ascii
    $s3 = "\"); return vEBo4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCo2 = new Function(\"vWHg2\", '{return vWHg2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLIf4 = new Function(\"vWH" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}