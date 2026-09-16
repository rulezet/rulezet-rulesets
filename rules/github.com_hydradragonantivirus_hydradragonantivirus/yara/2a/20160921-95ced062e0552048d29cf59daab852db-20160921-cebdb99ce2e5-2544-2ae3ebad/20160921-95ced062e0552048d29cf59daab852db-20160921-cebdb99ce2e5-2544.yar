rule _20160921_95ced062e0552048d29cf59daab852db_20160921_cebdb99ce2e5_2544 {
  meta:
    description = "datamaliciousorder - from files 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "tion f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2 = "urn \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3 = "00(){return \"Um\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp\"" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s5 = "\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function" ascii
    $s6 = "n \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(fu" ascii
    $s7 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"EZu\";})(),(fu" ascii
    $s8 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Qa\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}