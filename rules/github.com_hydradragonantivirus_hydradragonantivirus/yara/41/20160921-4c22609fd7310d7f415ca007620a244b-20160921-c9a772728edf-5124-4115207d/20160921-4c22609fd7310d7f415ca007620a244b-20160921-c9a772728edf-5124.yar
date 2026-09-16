rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_c9a772728edf_5124 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Qa\"" ascii
    $s2 = "\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f" ascii
    $s3 = "tion f000(){return \"RLk\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return" ascii
    $s4 = " \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = "(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Km\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}