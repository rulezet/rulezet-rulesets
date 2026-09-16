rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_c9a772728edf_5190 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f0" ascii
    $s2 = "on f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s3 = " f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"" ascii
    $s4 = "turn \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s5 = ";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}