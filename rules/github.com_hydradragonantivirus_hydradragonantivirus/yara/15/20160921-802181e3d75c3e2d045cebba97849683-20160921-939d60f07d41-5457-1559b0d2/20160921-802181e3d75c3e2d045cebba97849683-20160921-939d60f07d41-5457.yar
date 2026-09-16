rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_939d60f07d41_5457 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1 = "OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(funct" ascii
    $s2 = "z\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function" ascii
    $s3 = "unction f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s4 = "x\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function" ascii
    $s5 = "n \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}