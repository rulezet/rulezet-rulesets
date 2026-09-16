rule sig_20161206_3ec100f1413e43a4bea684f875dc03d5 {
  meta:
    description = "datamaliciousorder - file 20161206_3ec100f1413e43a4bea684f875dc03d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e869740e6e7fb02a5cef8c62998dfb1e6157ad97fbd612f7b90d48ce222d1c8e"

  strings:
    $s1 = "function _XHz0(s) {var _GJy7 = new Date();_GJy7.setUTCFullYear(\"2003\");if (_GJy7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XHz0(s) {var _GJy7 = new Date();_GJy7.setUTCFullYear(\"2003\");if (_GJy7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _KWj7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}