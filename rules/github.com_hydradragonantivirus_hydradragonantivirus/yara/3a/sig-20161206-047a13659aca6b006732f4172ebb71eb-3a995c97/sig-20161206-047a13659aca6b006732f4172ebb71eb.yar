rule sig_20161206_047a13659aca6b006732f4172ebb71eb {
  meta:
    description = "datamaliciousorder - file 20161206_047a13659aca6b006732f4172ebb71eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b19f2f60974827f4b7afb3c2ad90aa67bb135fa4c9b6313feb31963e26b06a"

  strings:
    $s1 = "function _ZGu5(s) {var _EKn5 = new Date();_EKn5.setUTCFullYear(\"2003\");if (_EKn5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZGu5(s) {var _EKn5 = new Date();_EKn5.setUTCFullYear(\"2003\");if (_EKn5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZOf3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}