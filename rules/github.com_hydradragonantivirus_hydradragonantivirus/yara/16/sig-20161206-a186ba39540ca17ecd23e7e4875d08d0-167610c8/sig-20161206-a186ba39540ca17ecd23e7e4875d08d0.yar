rule sig_20161206_a186ba39540ca17ecd23e7e4875d08d0 {
  meta:
    description = "datamaliciousorder - file 20161206_a186ba39540ca17ecd23e7e4875d08d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9703f1e60367e89aef7c425bc544b237f64584defa0bdafde345205d0bc176e"

  strings:
    $s1 = "var vKk3 = new Function(\"s\", '{var vCMo7 = new Date();vCMo7[\"setUTCFullYear\"](\"2003\");if (vCMo7.getUTCFullYear().toString(" ascii
    $s2 = "var vKk3 = new Function(\"s\", '{var vCMo7 = new Date();vCMo7[\"setUTCFullYear\"](\"2003\");if (vCMo7.getUTCFullYear().toString(" ascii
    $s3 = "function vYKq4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vGPj5 = s.split(\"##\"); return vGPj5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}