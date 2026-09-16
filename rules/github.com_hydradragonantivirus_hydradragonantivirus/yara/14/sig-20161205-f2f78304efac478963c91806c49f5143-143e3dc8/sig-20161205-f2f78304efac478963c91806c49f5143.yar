rule sig_20161205_f2f78304efac478963c91806c49f5143 {
  meta:
    description = "datamaliciousorder - file 20161205_f2f78304efac478963c91806c49f5143.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e4266b48c1945e184f29000c391586c274db1be65d639261dd77a6498b9e052"

  strings:
    $s1 = "function _PQs2(s) {var _RDa3 = new Date();_RDa3.setUTCFullYear(\"2003\");if (_RDa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PQs2(s) {var _RDa3 = new Date();_RDa3.setUTCFullYear(\"2003\");if (_RDa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _En1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}