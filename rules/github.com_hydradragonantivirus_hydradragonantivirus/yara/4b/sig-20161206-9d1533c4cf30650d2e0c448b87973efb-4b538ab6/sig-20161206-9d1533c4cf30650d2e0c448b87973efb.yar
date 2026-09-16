rule sig_20161206_9d1533c4cf30650d2e0c448b87973efb {
  meta:
    description = "datamaliciousorder - file 20161206_9d1533c4cf30650d2e0c448b87973efb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09e6f728d66e001086a82336a023aecf03babfc3a486293beb175acaf0d3adc6"

  strings:
    $s1 = "var vJBm4 = new Function(\"s\", '{var vGYu8 = new Date();vGYu8[\"setUTCFullYear\"](\"2003\");if (vGYu8.getUTCFullYear().toString" ascii
    $s2 = "var vJBm4 = new Function(\"s\", '{var vGYu8 = new Date();vGYu8[\"setUTCFullYear\"](\"2003\");if (vGYu8.getUTCFullYear().toString" ascii
    $s3 = "function vFx7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vRg0 = s.split(\"##\"); return vRg0.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}