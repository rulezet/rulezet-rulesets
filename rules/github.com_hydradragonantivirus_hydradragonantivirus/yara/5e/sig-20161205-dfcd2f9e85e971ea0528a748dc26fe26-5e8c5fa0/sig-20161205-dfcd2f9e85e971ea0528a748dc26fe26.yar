rule sig_20161205_dfcd2f9e85e971ea0528a748dc26fe26 {
  meta:
    description = "datamaliciousorder - file 20161205_dfcd2f9e85e971ea0528a748dc26fe26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28495670dd45bca7974847c5ff80216f985ce85c73ba81c3ade0bac881c4b786"

  strings:
    $s1 = "function _Rn4(s) {var _NCo9 = new Date();_NCo9.setUTCFullYear(\"2003\");if (_NCo9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Rn4(s) {var _NCo9 = new Date();_NCo9.setUTCFullYear(\"2003\");if (_NCo9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZWw6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}