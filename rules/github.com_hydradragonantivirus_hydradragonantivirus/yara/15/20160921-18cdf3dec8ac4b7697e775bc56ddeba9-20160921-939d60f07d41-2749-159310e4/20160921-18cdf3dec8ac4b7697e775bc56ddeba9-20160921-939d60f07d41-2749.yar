rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_939d60f07d41_2749 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f00" ascii
    $s2 = "),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "rn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4 = "ion f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s5 = "tion f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s6 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s7 = "f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}