rule sig_20161205_53939bb56e618e3c0a7b7e72cfe4e810 {
  meta:
    description = "datamaliciousorder - file 20161205_53939bb56e618e3c0a7b7e72cfe4e810.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0435b286a716bdad32372c2960694e64581915bab38d49e7372abd3cfc63cb6d"

  strings:
    $s1 = "function _Ih5(s) {var _Uo5 = new Date();_Uo5.setUTCFullYear(\"2003\");if (_Uo5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ih5(s) {var _Uo5 = new Date();_Uo5.setUTCFullYear(\"2003\");if (_Uo5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Pz6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}