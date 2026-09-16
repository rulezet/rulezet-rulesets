rule sig_20161206_21651ea074d286f478609c81f385e6de {
  meta:
    description = "datamaliciousorder - file 20161206_21651ea074d286f478609c81f385e6de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d80212e725a3756e07d5271b531fe2ac07e9049f0acf0752a7ea965246d827d7"

  strings:
    $s1 = "var vWq0 = new Function(\"s\", '{var vLTt7 = new Date();vLTt7[\"setUTCFullYear\"](\"2003\");if (vLTt7.getUTCFullYear().toString(" ascii
    $s2 = "var vWq0 = new Function(\"s\", '{var vLTt7 = new Date();vLTt7[\"setUTCFullYear\"](\"2003\");if (vLTt7.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vQOk4 = s.split(\"##\"); return vQOk4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vZq6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}