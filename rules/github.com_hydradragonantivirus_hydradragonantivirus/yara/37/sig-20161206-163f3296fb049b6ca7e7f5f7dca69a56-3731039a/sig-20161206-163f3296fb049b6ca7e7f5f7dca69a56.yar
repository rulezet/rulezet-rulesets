rule sig_20161206_163f3296fb049b6ca7e7f5f7dca69a56 {
  meta:
    description = "datamaliciousorder - file 20161206_163f3296fb049b6ca7e7f5f7dca69a56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47bf55a349eb806ec33d44a601d62cc7adc20de2e7b74934cd88cd9ad016a106"

  strings:
    $s1 = "var vQy1 = new Function(\"s\", '{var vIQl6 = new Date();vIQl6[\"setUTCFullYear\"](\"2003\");if (vIQl6.getUTCFullYear().toString(" ascii
    $s2 = "var vQy1 = new Function(\"s\", '{var vIQl6 = new Date();vIQl6[\"setUTCFullYear\"](\"2003\");if (vIQl6.getUTCFullYear().toString(" ascii
    $s3 = "function vLVr2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vVBf1 = s.split(\"##\"); return vVBf1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}