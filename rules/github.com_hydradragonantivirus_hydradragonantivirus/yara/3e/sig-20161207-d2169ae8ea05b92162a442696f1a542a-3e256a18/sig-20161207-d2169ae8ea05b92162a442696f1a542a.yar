rule sig_20161207_d2169ae8ea05b92162a442696f1a542a {
  meta:
    description = "datamaliciousorder - file 20161207_d2169ae8ea05b92162a442696f1a542a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4112d6a20eafe6470c56b004020f4f401918423b330925dea263a94ef57a8bda"

  strings:
    $s1 = "var vRj7 = new Function(\"vEWb4\", '{return vEWb4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDQt6 = new Function(\"vEW" ascii
    $s2 = "2 = new Date();vTKl2[\"setUTCFullYear\"](\"2003\");if (vTKl2.getUTCFullYear().toString(10) == \"2003\") {var vHo7 = vEWb4.split(" ascii
    $s3 = "); return vHo7.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRj7 = new Function(\"vEWb4\", '{return vEWb4[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vDQt6 = new Function(\"vEW" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}