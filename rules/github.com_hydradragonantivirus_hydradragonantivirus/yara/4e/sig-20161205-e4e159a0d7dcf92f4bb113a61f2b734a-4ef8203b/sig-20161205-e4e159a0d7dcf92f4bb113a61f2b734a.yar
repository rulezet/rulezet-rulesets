rule sig_20161205_e4e159a0d7dcf92f4bb113a61f2b734a {
  meta:
    description = "datamaliciousorder - file 20161205_e4e159a0d7dcf92f4bb113a61f2b734a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cbc2fa0633945c603f0299b6a786d098cedf4652a45471e5e9fab439d91064f"

  strings:
    $s1 = "function _Ms4(s) {var _Fp3 = new Date();_Fp3.setUTCFullYear(\"2003\");if (_Fp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ms4(s) {var _Fp3 = new Date();_Fp3.setUTCFullYear(\"2003\");if (_Fp3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qs9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}