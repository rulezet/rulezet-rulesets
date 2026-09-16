rule sig_20161207_03a864ac5730b168b36af29a465d23af {
  meta:
    description = "datamaliciousorder - file 20161207_03a864ac5730b168b36af29a465d23af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8ed87229665c55fb7474d399f632e78476996d41c1bc17ba546164fbecb0cdb"

  strings:
    $s1 = " new Date();vCf9[\"setUTCFullYear\"](\"2003\");if (vCf9.getUTCFullYear().toString(10) == \"2003\") {var vZYa2 = vSn7.split(\"###" ascii
    $s2 = "var vGAf3 = new Function(\"vSn7\", '{return vSn7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOAh7 = new Function(\"vSn7" ascii
    $s3 = "turn vZYa2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGAf3 = new Function(\"vSn7\", '{return vSn7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vOAh7 = new Function(\"vSn7" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}