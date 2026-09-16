rule sig_20161206_4ab780aaf1600307e1f7655f1cadacbe {
  meta:
    description = "datamaliciousorder - file 20161206_4ab780aaf1600307e1f7655f1cadacbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bce12c3c799eca3f24b2da62c98b7d77420bb05cf2953abc98e5a0419ae19a3"

  strings:
    $s1 = "var vBm5 = new Function(\"s\", '{var vTFv1 = new Date();vTFv1[\"setUTCFullYear\"](\"2003\");if (vTFv1.getUTCFullYear().toString(" ascii
    $s2 = "var vBm5 = new Function(\"s\", '{var vTFv1 = new Date();vTFv1[\"setUTCFullYear\"](\"2003\");if (vTFv1.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vZc4 = s.split(\"##\"); return vZc4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQn2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}