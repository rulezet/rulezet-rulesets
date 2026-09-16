rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_cdeac57ac549_2548 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Ml" ascii
    $s2 = "){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";" ascii
    $s3 = "turn \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"XTn\";})()," ascii
    $s4 = "nction f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Qa\";})(),(function " ascii
    $s6 = "on f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s7 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sv\";})(),(f" ascii
    $s8 = "return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}