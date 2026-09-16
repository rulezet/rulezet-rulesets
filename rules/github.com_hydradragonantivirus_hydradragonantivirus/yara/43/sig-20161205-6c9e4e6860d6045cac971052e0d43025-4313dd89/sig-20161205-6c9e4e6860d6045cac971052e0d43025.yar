rule sig_20161205_6c9e4e6860d6045cac971052e0d43025 {
  meta:
    description = "datamaliciousorder - file 20161205_6c9e4e6860d6045cac971052e0d43025.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7493dbea80bc2e3fcf60977296544662aa7098bf3741e204c765d828a03c9fc3"

  strings:
    $s1 = "function _SIz1(s) {var _XXd8 = new Date();_XXd8.setUTCFullYear(\"2003\");if (_XXd8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SIz1(s) {var _XXd8 = new Date();_XXd8.setUTCFullYear(\"2003\");if (_XXd8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ne0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}