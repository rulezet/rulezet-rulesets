rule sig_20161206_317812b22ddd7a6321de1a7a136ebadf {
  meta:
    description = "datamaliciousorder - file 20161206_317812b22ddd7a6321de1a7a136ebadf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4d69ca4987344715ac80a839e02b7f09101972a9a784eb1751bcc4d5106fc92"

  strings:
    $s1 = "var vSc5 = new Function(\"s\", '{var vTGr4 = new Date();vTGr4[\"setUTCFullYear\"](\"2003\");if (vTGr4.getUTCFullYear().toString(" ascii
    $s2 = "var vSc5 = new Function(\"s\", '{var vTGr4 = new Date();vTGr4[\"setUTCFullYear\"](\"2003\");if (vTGr4.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vNMh1 = s.split(\"##\"); return vNMh1.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBUz2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}