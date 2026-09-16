rule sig_20161208_58aebb703e4777c41e487b49e6b0f687 {
  meta:
    description = "datamaliciousorder - file 20161208_58aebb703e4777c41e487b49e6b0f687.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e79fd556cec55bfa6c8338425fef6e4f6cb6c87cf5bca8a0d663bac535c1e9b7"

  strings:
    $s1 = "var vFl2 = new Function(\"vUBx6\", '{return vUBx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSc2 = new Function(\"vUBx" ascii
    $s2 = " = new Date();vXLk4[\"setUTC\"+\"FullYear\"](\"2003\");if (vXLk4.getUTCFullYear().toString(10) == \"2003\") {var vPy5 = vUBx6.sp" ascii
    $s3 = "#\"); return vPy5.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFl2 = new Function(\"vUBx6\", '{return vUBx6[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vSc2 = new Function(\"vUBx" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}