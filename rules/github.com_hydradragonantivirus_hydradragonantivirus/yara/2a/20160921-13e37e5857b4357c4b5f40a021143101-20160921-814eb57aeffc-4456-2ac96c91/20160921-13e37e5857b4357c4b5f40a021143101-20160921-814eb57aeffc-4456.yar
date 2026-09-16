rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_814eb57aeffc_4456 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash3       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1 = "Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function" ascii
    $s2 = "})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f00" ascii
    $s3 = "u\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function " ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";}" ascii
    $s5 = "ion f000(){return \"Uo\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}