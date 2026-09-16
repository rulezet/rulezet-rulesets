rule _20160921_cdeac57ac549120611856c7af0c490f6_20160921_f1b8df0ab75a_5694 {
  meta:
    description = "datamaliciousorder - from files 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash2       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc" ascii
    $s2 = " \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s3 = "turn \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f" ascii
    $s5 = "on f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}