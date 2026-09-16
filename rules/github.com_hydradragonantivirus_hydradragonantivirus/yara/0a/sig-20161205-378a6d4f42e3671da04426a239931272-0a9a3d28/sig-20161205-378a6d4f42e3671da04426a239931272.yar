rule sig_20161205_378a6d4f42e3671da04426a239931272 {
  meta:
    description = "datamaliciousorder - file 20161205_378a6d4f42e3671da04426a239931272.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f968b2f3935e0a56100ba20c3167a80fedba55b8e665791147d0808edb40ab5"

  strings:
    $s1 = "function _Be2(s) {var _At6 = new Date();_At6.setUTCFullYear(\"2003\");if (_At6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Be2(s) {var _At6 = new Date();_At6.setUTCFullYear(\"2003\");if (_At6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ESq6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}