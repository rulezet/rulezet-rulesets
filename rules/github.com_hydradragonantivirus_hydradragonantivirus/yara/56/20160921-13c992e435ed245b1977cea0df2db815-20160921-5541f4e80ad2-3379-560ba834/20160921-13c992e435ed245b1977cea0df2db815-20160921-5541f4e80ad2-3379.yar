rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_5541f4e80ad2_3379 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"

  strings:
    $s1 = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj" ascii
    $s2 = "turn \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s3 = "on f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s4 = "ion f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s5 = "){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(" ascii
    $s6 = "ion f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}