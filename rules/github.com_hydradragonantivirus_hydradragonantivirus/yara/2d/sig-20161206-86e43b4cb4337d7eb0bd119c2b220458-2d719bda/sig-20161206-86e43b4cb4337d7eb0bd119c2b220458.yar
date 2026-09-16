rule sig_20161206_86e43b4cb4337d7eb0bd119c2b220458 {
  meta:
    description = "datamaliciousorder - file 20161206_86e43b4cb4337d7eb0bd119c2b220458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06bfd95c23d1966997e87e3407e0417fcba748eef20ba7ff4f6f75b19a440283"

  strings:
    $s1 = "var vYWp9 = new Function(\"s\", '{var vSb4 = new Date();vSb4[\"setUTCFullYear\"](\"2003\");if (vSb4.getUTCFullYear().toString(10" ascii
    $s2 = "var vYWp9 = new Function(\"s\", '{var vSb4 = new Date();vSb4[\"setUTCFullYear\"](\"2003\");if (vSb4.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vQZs2 = s.split(\"##\"); return vQZs2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vNZw9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}