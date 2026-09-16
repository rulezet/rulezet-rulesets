rule _20160921_4ad5ed78dc05b02005f65ab785b9c74a_20160921_8ac006dedc62_5092 {
  meta:
    description = "datamaliciousorder - from files 20160921_4ad5ed78dc05b02005f65ab785b9c74a.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e5f9d362688f19111d3dbdf393d51e133fcc63eb7db27536cb31d1205ccc9e3"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = "unction f000(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){ret" ascii
    $s2 = "){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";}" ascii
    $s3 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){r" ascii
    $s4 = "00(){return \"DNa\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s5 = "\"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}