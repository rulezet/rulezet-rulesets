rule sig_20161205_b3a4e257e38fa3c432e180978d59dfbe {
  meta:
    description = "datamaliciousorder - file 20161205_b3a4e257e38fa3c432e180978d59dfbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d80d61518b93d12196aa9009265cc6aa74d375bfd90f113338f4e9929b16e7"

  strings:
    $s1 = "function _Ex6(s) {var _IJa7 = new Date();_IJa7.setUTCFullYear(\"2003\");if (_IJa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ex6(s) {var _IJa7 = new Date();_IJa7.setUTCFullYear(\"2003\");if (_IJa7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _KZc0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}