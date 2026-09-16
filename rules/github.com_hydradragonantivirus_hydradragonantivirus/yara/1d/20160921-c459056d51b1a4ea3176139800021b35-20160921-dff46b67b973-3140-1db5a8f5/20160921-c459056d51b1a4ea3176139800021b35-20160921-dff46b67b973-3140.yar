rule _20160921_c459056d51b1a4ea3176139800021b35_20160921_dff46b67b973_3140 {
  meta:
    description = "datamaliciousorder - from files 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functio" ascii
    $s2 = "(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s3 = "000(){return \"Kw\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s4 = "eturn \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";})()," ascii
    $s5 = "e\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function " ascii
    $s6 = "00(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn" ascii
    $s7 = "urn \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}