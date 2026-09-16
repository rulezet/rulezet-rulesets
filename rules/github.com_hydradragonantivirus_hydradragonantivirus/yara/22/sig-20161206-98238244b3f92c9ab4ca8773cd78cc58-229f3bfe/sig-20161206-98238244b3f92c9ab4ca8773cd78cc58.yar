rule sig_20161206_98238244b3f92c9ab4ca8773cd78cc58 {
  meta:
    description = "datamaliciousorder - file 20161206_98238244b3f92c9ab4ca8773cd78cc58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4157a5722d05841d0150fd606311df9d1af67ed11e771f80a60eb2916db0f32"

  strings:
    $s1 = "var vGWj0 = new Function(\"s\", '{var vUc7 = new Date();vUc7[\"setUTCFullYear\"](\"2003\");if (vUc7.getUTCFullYear().toString(10" ascii
    $s2 = "var vGWj0 = new Function(\"s\", '{var vUc7 = new Date();vUc7[\"setUTCFullYear\"](\"2003\");if (vUc7.getUTCFullYear().toString(10" ascii
    $s3 = "function vHy5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vSi0 = s.split(\"##\"); return vSi0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}