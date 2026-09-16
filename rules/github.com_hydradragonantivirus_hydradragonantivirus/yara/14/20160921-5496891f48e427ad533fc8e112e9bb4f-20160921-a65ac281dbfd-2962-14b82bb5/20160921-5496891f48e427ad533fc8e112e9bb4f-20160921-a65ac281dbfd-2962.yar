rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_a65ac281dbfd_2962 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"

  strings:
    $s1 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})(" ascii
    $s2 = "unction f000(){return \"ZGq\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"Wh\";})(),(function f000(){retu" ascii
    $s3 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s4 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function" ascii
    $s5 = "(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s6 = " \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s7 = "0(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}