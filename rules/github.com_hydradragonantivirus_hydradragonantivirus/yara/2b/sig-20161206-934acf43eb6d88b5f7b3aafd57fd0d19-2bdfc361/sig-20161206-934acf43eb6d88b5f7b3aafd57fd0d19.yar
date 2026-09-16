rule sig_20161206_934acf43eb6d88b5f7b3aafd57fd0d19 {
  meta:
    description = "datamaliciousorder - file 20161206_934acf43eb6d88b5f7b3aafd57fd0d19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc8261957add6f0f37c284eb9876a09e91a3920a2123823f28295ab45de2b186"

  strings:
    $s1 = "function _ZRr9(s) {var _QIu4 = new Date();_QIu4.setUTCFullYear(\"2003\");if (_QIu4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZRr9(s) {var _QIu4 = new Date();_QIu4.setUTCFullYear(\"2003\");if (_QIu4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _SXh9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}