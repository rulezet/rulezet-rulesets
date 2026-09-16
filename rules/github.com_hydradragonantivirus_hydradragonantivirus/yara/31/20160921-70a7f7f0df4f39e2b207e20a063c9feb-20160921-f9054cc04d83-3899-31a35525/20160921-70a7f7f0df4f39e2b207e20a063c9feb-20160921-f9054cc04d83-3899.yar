rule _20160921_70a7f7f0df4f39e2b207e20a063c9feb_20160921_f9054cc04d83_3899 {
  meta:
    description = "datamaliciousorder - from files 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = ",(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f000(){" ascii
    $s2 = " f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Y" ascii
    $s3 = "(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){r" ascii
    $s4 = "n \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(func" ascii
    $s5 = " \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s6 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Rh\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}