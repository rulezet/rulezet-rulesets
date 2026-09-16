rule sig_20161206_20386260922dad47605096e8253dacdc {
  meta:
    description = "datamaliciousorder - file 20161206_20386260922dad47605096e8253dacdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26143458a1c4e21691fe93aada23151204eb208f8c8d42ce7e55abe0015dca6a"

  strings:
    $s1 = "function _JCx7(s) {var _IJi7 = new Date();_IJi7.setUTCFullYear(\"2003\");if (_IJi7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JCx7(s) {var _IJi7 = new Date();_IJi7.setUTCFullYear(\"2003\");if (_IJi7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Pt2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}